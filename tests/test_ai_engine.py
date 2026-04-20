"""
Unit tests for the AI Engine.

Tests prompt construction, backend dispatch, fallback behavior,
and health checking with mocked HTTP responses.
"""

from unittest.mock import patch, MagicMock

import pytest

from app.ai_engine import (
    analyze,
    check_ai_health,
    _build_analysis_prompt,
    _build_system_prompt,
    _generate_fallback_analysis,
)
from app.config import AIBackend, Settings
from app.models import (
    BlastRadius,
    IncidentMatch,
    PolicyViolation,
    RiskClassification,
    Severity,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_violations():
    """Sample policy violations for testing."""
    return [
        PolicyViolation(
            rule_id="R001",
            rule_name="Public IP / Open CIDR Block",
            severity=Severity.CRITICAL,
            message="Detects unrestricted network access via 0.0.0.0/0",
            line_hint='source_ranges = ["0.0.0.0/0"]',
        ),
    ]


@pytest.fixture
def sample_incidents():
    """Sample matched incidents for testing."""
    return [
        IncidentMatch(
            service="auth-service",
            issue="Public endpoint exposed after firewall misconfiguration",
            severity="Critical",
            date="2025-08-22",
            root_cause="Firewall rule allowed 0.0.0.0/0 ingress",
            resolution="Reverted firewall rule",
            mttr_hours=1.2,
        ),
    ]


@pytest.fixture
def service_context():
    """Sample service context for testing."""
    return {
        "criticality": "Critical",
        "dependencies": ["payment-api", "user-dashboard"],
        "owner": "Sarah Chen",
        "team": "Platform Engineering",
        "sla_tier": "Tier-1 (99.99%)",
    }


@pytest.fixture
def ollama_settings():
    """Settings configured for Ollama backend."""
    return Settings(ai_backend=AIBackend.OLLAMA)


@pytest.fixture
def openai_settings():
    """Settings configured for OpenAI backend."""
    return Settings(
        ai_backend=AIBackend.OPENAI,
        openai_api_key="test-key-123",
    )


@pytest.fixture
def no_ai_settings():
    """Settings with AI disabled."""
    return Settings(ai_backend=AIBackend.NONE)


# ── Prompt Construction Tests ────────────────────────────────────────────────

class TestPromptConstruction:
    """Test that prompts are constructed correctly."""

    def test_system_prompt_has_role(self):
        """System prompt should define the SRE role."""
        prompt = _build_system_prompt()
        assert "RELEASE RISK ENGINEER" in prompt.upper()
        assert "financial" in prompt.lower()

    def test_analysis_prompt_includes_terraform(self, sample_violations, sample_incidents, service_context):
        """Analysis prompt should include the Terraform code."""
        prompt = _build_analysis_prompt(
            terraform_code="resource \"test\" {}",
            service_name="auth-service",
            environment="Production",
            service_context=service_context,
            violations=sample_violations,
            matched_incidents=sample_incidents,
            classification=RiskClassification.HOLD,
            blast_radius=BlastRadius.HIGH,
        )
        assert "resource \"test\" {}" in prompt
        assert "auth-service" in prompt
        assert "Production" in prompt
        assert "Critical" in prompt

    def test_analysis_prompt_includes_violations(self, sample_violations, sample_incidents, service_context):
        """Prompt should include policy violation details."""
        prompt = _build_analysis_prompt(
            terraform_code="test code",
            service_name="auth-service",
            environment="Production",
            service_context=service_context,
            violations=sample_violations,
            matched_incidents=sample_incidents,
            classification=RiskClassification.HOLD,
            blast_radius=BlastRadius.HIGH,
        )
        assert "R001" in prompt
        assert "Public IP" in prompt

    def test_analysis_prompt_includes_incidents(self, sample_violations, sample_incidents, service_context):
        """Prompt should include historical incident data."""
        prompt = _build_analysis_prompt(
            terraform_code="test code",
            service_name="auth-service",
            environment="Production",
            service_context=service_context,
            violations=sample_violations,
            matched_incidents=sample_incidents,
            classification=RiskClassification.HOLD,
            blast_radius=BlastRadius.HIGH,
        )
        assert "2025-08-22" in prompt
        assert "firewall" in prompt.lower()


# ── Fallback Analysis Tests ──────────────────────────────────────────────────

class TestFallbackAnalysis:
    """Test the deterministic fallback analysis."""

    def test_fallback_includes_classification(self, sample_violations, sample_incidents, service_context):
        """Fallback should mention the classification."""
        result = _generate_fallback_analysis(
            RiskClassification.HOLD,
            sample_violations,
            sample_incidents,
            service_context,
        )
        assert "HOLD" in result

    def test_fallback_includes_violations(self, sample_violations, service_context):
        """Fallback should list violations."""
        result = _generate_fallback_analysis(
            RiskClassification.HOLD,
            sample_violations,
            [],
            service_context,
        )
        assert "R001" in result

    def test_fallback_includes_incident_warning(self, sample_violations, sample_incidents, service_context):
        """Fallback should warn about repeat failure patterns."""
        result = _generate_fallback_analysis(
            RiskClassification.HOLD,
            sample_violations,
            sample_incidents,
            service_context,
        )
        assert "Repeat Failure" in result or "past incidents" in result.lower()

    def test_fallback_mentions_policy_engine_note(self, service_context):
        """Fallback should note it's from the deterministic engine."""
        result = _generate_fallback_analysis(
            RiskClassification.SAFE,
            [],
            [],
            service_context,
        )
        assert "deterministic" in result.lower() or "policy engine" in result.lower()

    def test_fallback_safe_classification(self, service_context):
        """SAFE classification with no violations."""
        result = _generate_fallback_analysis(
            RiskClassification.SAFE,
            [],
            [],
            service_context,
        )
        assert "SAFE" in result


# ── AI Backend Dispatch Tests ────────────────────────────────────────────────

class TestAIBackendDispatch:
    """Test that the correct AI backend is called."""

    def test_none_backend_returns_fallback(self, no_ai_settings, sample_violations, service_context):
        """AI_BACKEND=none should return fallback analysis without HTTP calls."""
        result = analyze(
            terraform_code="test code",
            service_name="auth-service",
            environment="Production",
            service_context=service_context,
            violations=sample_violations,
            matched_incidents=[],
            classification=RiskClassification.HOLD,
            blast_radius=BlastRadius.HIGH,
            settings=no_ai_settings,
        )
        assert result  # Should not be empty
        assert "policy engine" in result.lower() or "deterministic" in result.lower()

    @patch("app.ai_engine.requests.post")
    def test_ollama_backend_called(self, mock_post, ollama_settings, sample_violations, service_context):
        """AI_BACKEND=ollama should call the Ollama API."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"response": "AI analysis result"}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        result = analyze(
            terraform_code="test code",
            service_name="auth-service",
            environment="Production",
            service_context=service_context,
            violations=sample_violations,
            matched_incidents=[],
            classification=RiskClassification.HOLD,
            blast_radius=BlastRadius.HIGH,
            settings=ollama_settings,
        )
        assert result == "AI analysis result"
        mock_post.assert_called_once()

    @patch("app.ai_engine.requests.post")
    def test_openai_backend_called(self, mock_post, openai_settings, sample_violations, service_context):
        """AI_BACKEND=openai should call the OpenAI API."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "OpenAI analysis"}}]
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        result = analyze(
            terraform_code="test code",
            service_name="auth-service",
            environment="Production",
            service_context=service_context,
            violations=sample_violations,
            matched_incidents=[],
            classification=RiskClassification.HOLD,
            blast_radius=BlastRadius.HIGH,
            settings=openai_settings,
        )
        assert result == "OpenAI analysis"

    @patch("app.ai_engine.requests.post", side_effect=ConnectionError("Connection refused"))
    def test_connection_error_fallback(self, mock_post, ollama_settings, sample_violations, service_context):
        """Connection errors should gracefully fall back."""
        result = analyze(
            terraform_code="test code",
            service_name="auth-service",
            environment="Production",
            service_context=service_context,
            violations=sample_violations,
            matched_incidents=[],
            classification=RiskClassification.HOLD,
            blast_radius=BlastRadius.HIGH,
            settings=ollama_settings,
        )
        assert result  # Should return fallback, not crash


# ── Health Check Tests ───────────────────────────────────────────────────────

class TestHealthCheck:
    """Test AI backend health checking."""

    def test_none_backend_not_available(self, no_ai_settings):
        """AI_BACKEND=none should report as unavailable."""
        assert check_ai_health(no_ai_settings) is False

    @patch("app.ai_engine.requests.get")
    def test_ollama_health_check(self, mock_get, ollama_settings):
        """Ollama health check should verify the server is up."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        assert check_ai_health(ollama_settings) is True

    @patch("app.ai_engine.requests.get", side_effect=ConnectionError)
    def test_ollama_unreachable(self, mock_get, ollama_settings):
        """Unreachable Ollama should return False."""
        assert check_ai_health(ollama_settings) is False

    def test_openai_health_with_key(self, openai_settings):
        """OpenAI with API key set should report available."""
        assert check_ai_health(openai_settings) is True

    def test_openai_health_without_key(self):
        """OpenAI without API key should report unavailable."""
        settings = Settings(ai_backend=AIBackend.OPENAI, openai_api_key="")
        assert check_ai_health(settings) is False
