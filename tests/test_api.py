"""
Integration tests for the FastAPI API endpoints.

Uses FastAPI's TestClient to test all endpoints end-to-end,
including request validation, error handling, and the full
analysis pipeline.
"""

import json
import os
import tempfile
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.config import AIBackend, Settings


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def test_app(sample_service_map, sample_incidents):
    """Create a test FastAPI app with isolated test data."""
    # Create temp data directory
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "service_map.json"), "w") as f:
            json.dump(sample_service_map, f)
        with open(os.path.join(tmpdir, "incident_history.json"), "w") as f:
            json.dump(sample_incidents, f)

        # Configure settings
        test_settings = Settings(
            ai_backend=AIBackend.NONE,
            data_dir=tmpdir,
        )

        # Patch settings and reset policy engine
        with patch("app.main.get_settings", return_value=test_settings), \
             patch("app.config.get_settings", return_value=test_settings):
            # Reset the global policy engine
            import app.main as main_module
            main_module._policy_engine = None

            from app.main import app
            from app.policy_engine import PolicyEngine
            main_module._policy_engine = PolicyEngine(data_dir=tmpdir)

            client = TestClient(app)
            yield client

            # Cleanup
            main_module._policy_engine = None


# ── Health Check Tests ───────────────────────────────────────────────────────

class TestHealthEndpoint:
    """Test the /health endpoint."""

    def test_health_check_returns_200(self, test_app):
        """Health endpoint should return 200."""
        response = test_app.get("/health")
        assert response.status_code == 200

    def test_health_check_response_format(self, test_app):
        """Health response should include status, version, and AI info."""
        response = test_app.get("/health")
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "ai_backend" in data
        assert "ai_available" in data


# ── Services Endpoint Tests ──────────────────────────────────────────────────

class TestServicesEndpoint:
    """Test the /services endpoint."""

    def test_list_services_returns_200(self, test_app):
        """Services endpoint should return 200."""
        response = test_app.get("/services")
        assert response.status_code == 200

    def test_list_services_returns_all(self, test_app):
        """Should return all services from the service map."""
        response = test_app.get("/services")
        data = response.json()
        names = [s["name"] for s in data]
        assert "auth-service" in names
        assert "payment-api" in names
        assert "monitoring-agent" in names

    def test_service_has_required_fields(self, test_app):
        """Each service should have name, criticality, and dependencies."""
        response = test_app.get("/services")
        data = response.json()
        for service in data:
            assert "name" in service
            assert "criticality" in service
            assert "dependencies" in service


# ── History Endpoint Tests ───────────────────────────────────────────────────

class TestHistoryEndpoint:
    """Test the /history/{service_name} endpoint."""

    def test_get_history_known_service(self, test_app):
        """Should return incidents for a known service."""
        response = test_app.get("/history/auth-service")
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "auth-service"
        assert len(data["incidents"]) >= 1

    def test_get_history_unknown_service(self, test_app):
        """Should return 404 for unknown service."""
        response = test_app.get("/history/nonexistent-service")
        assert response.status_code == 404

    def test_history_has_incident_details(self, test_app):
        """Incidents should have required detail fields."""
        response = test_app.get("/history/auth-service")
        data = response.json()
        if data["incidents"]:
            inc = data["incidents"][0]
            assert "service" in inc
            assert "issue" in inc
            assert "severity" in inc


# ── Analyze Endpoint Tests ───────────────────────────────────────────────────

class TestAnalyzeEndpoint:
    """Test the /analyze endpoint — the core analysis pipeline."""

    def test_analyze_safe_code_returns_200(self, test_app, safe_terraform):
        """Safe Terraform code should return 200."""
        response = test_app.post("/analyze", json={
            "service_name": "monitoring-agent",
            "environment": "Development",
            "terraform_code": safe_terraform,
            "dry_run": True,
        })
        assert response.status_code == 200

    def test_analyze_safe_code_classification(self, test_app, safe_terraform):
        """Safe code should be classified as SAFE."""
        response = test_app.post("/analyze", json={
            "service_name": "monitoring-agent",
            "environment": "Development",
            "terraform_code": safe_terraform,
            "dry_run": True,
        })
        data = response.json()
        assert data["classification"] == "SAFE"

    def test_analyze_risky_code_classification(self, test_app, risky_terraform):
        """Risky code should be classified as HOLD."""
        response = test_app.post("/analyze", json={
            "service_name": "auth-service",
            "environment": "Production",
            "terraform_code": risky_terraform,
            "dry_run": True,
        })
        data = response.json()
        assert data["classification"] == "HOLD"

    def test_analyze_risky_code_has_violations(self, test_app, risky_terraform):
        """Risky code should include policy violations."""
        response = test_app.post("/analyze", json={
            "service_name": "auth-service",
            "environment": "Production",
            "terraform_code": risky_terraform,
            "dry_run": True,
        })
        data = response.json()
        assert len(data["policy_violations"]) >= 3

    def test_analyze_response_has_all_fields(self, test_app, safe_terraform):
        """Response should include all RiskAssessment fields."""
        response = test_app.post("/analyze", json={
            "service_name": "monitoring-agent",
            "environment": "Development",
            "terraform_code": safe_terraform,
            "dry_run": True,
        })
        data = response.json()
        required_fields = [
            "classification", "blast_radius", "confidence_score",
            "policy_violations", "matched_incidents", "rollout_guidance",
            "service_context",
        ]
        for field in required_fields:
            assert field in data, f"Missing field: {field}"

    def test_analyze_unknown_service_returns_404(self, test_app):
        """Unknown service should return 404."""
        response = test_app.post("/analyze", json={
            "service_name": "nonexistent-service",
            "environment": "Development",
            "terraform_code": "resource {}",
            "dry_run": True,
        })
        assert response.status_code == 404

    def test_analyze_empty_terraform_rejected(self, test_app):
        """Empty Terraform code should be rejected (422 validation error)."""
        response = test_app.post("/analyze", json={
            "service_name": "auth-service",
            "environment": "Production",
            "terraform_code": "",
            "dry_run": True,
        })
        assert response.status_code == 422

    def test_analyze_invalid_environment(self, test_app):
        """Invalid environment value should be rejected."""
        response = test_app.post("/analyze", json={
            "service_name": "auth-service",
            "environment": "InvalidEnv",
            "terraform_code": "resource {}",
            "dry_run": True,
        })
        assert response.status_code == 422

    def test_analyze_blast_radius_critical_service(self, test_app, risky_terraform):
        """Critical service should have high blast radius."""
        response = test_app.post("/analyze", json={
            "service_name": "auth-service",
            "environment": "Production",
            "terraform_code": risky_terraform,
            "dry_run": True,
        })
        data = response.json()
        assert data["blast_radius"] == "High"

    def test_analyze_rollout_guidance_present(self, test_app, risky_terraform):
        """Response should include rollout guidance."""
        response = test_app.post("/analyze", json={
            "service_name": "auth-service",
            "environment": "Production",
            "terraform_code": risky_terraform,
            "dry_run": True,
        })
        data = response.json()
        assert data["rollout_guidance"]
        assert len(data["rollout_guidance"]) > 10

    def test_analyze_service_context_in_response(self, test_app, safe_terraform):
        """Response should include service context metadata."""
        response = test_app.post("/analyze", json={
            "service_name": "auth-service",
            "environment": "Development",
            "terraform_code": safe_terraform,
            "dry_run": True,
        })
        data = response.json()
        assert data["service_context"]["criticality"] == "Critical"
