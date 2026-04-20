"""
Unit tests for Pydantic data models.

Tests model validation, serialization, and enum behavior.
"""

import pytest
from pydantic import ValidationError

from app.models import (
    BlastRadius,
    Environment,
    PolicyViolation,
    ReleaseRequest,
    RiskAssessment,
    RiskClassification,
    Severity,
)


class TestReleaseRequest:
    """Test ReleaseRequest model validation."""

    def test_valid_request(self):
        """Valid request should parse successfully."""
        req = ReleaseRequest(
            service_name="auth-service",
            environment=Environment.PRODUCTION,
            terraform_code="resource {}",
        )
        assert req.service_name == "auth-service"
        assert req.environment == Environment.PRODUCTION
        assert req.dry_run is False

    def test_empty_terraform_code_rejected(self):
        """Empty terraform_code should be rejected (min_length=1)."""
        with pytest.raises(ValidationError):
            ReleaseRequest(
                service_name="auth-service",
                environment=Environment.PRODUCTION,
                terraform_code="",
            )

    def test_missing_service_name_rejected(self):
        """Missing service_name should be rejected."""
        with pytest.raises(ValidationError):
            ReleaseRequest(
                environment=Environment.PRODUCTION,
                terraform_code="resource {}",
            )

    def test_invalid_environment_rejected(self):
        """Invalid environment value should be rejected."""
        with pytest.raises(ValidationError):
            ReleaseRequest(
                service_name="auth-service",
                environment="InvalidEnv",
                terraform_code="resource {}",
            )

    def test_dry_run_flag(self):
        """dry_run should default to False."""
        req = ReleaseRequest(
            service_name="test",
            environment=Environment.DEVELOPMENT,
            terraform_code="resource {}",
        )
        assert req.dry_run is False

        req_dry = ReleaseRequest(
            service_name="test",
            environment=Environment.DEVELOPMENT,
            terraform_code="resource {}",
            dry_run=True,
        )
        assert req_dry.dry_run is True


class TestPolicyViolation:
    """Test PolicyViolation model."""

    def test_valid_violation(self):
        """Valid violation should parse successfully."""
        v = PolicyViolation(
            rule_id="R001",
            rule_name="Test Rule",
            severity=Severity.CRITICAL,
            message="Test violation message",
        )
        assert v.rule_id == "R001"
        assert v.severity == Severity.CRITICAL
        assert v.line_hint == ""  # Default

    def test_violation_with_line_hint(self):
        """Violation should accept optional line_hint."""
        v = PolicyViolation(
            rule_id="R001",
            rule_name="Test Rule",
            severity=Severity.HIGH,
            message="Test message",
            line_hint="source_ranges = [\"0.0.0.0/0\"]",
        )
        assert "0.0.0.0/0" in v.line_hint


class TestRiskAssessment:
    """Test RiskAssessment model."""

    def test_valid_assessment(self):
        """Valid assessment should parse successfully."""
        assessment = RiskAssessment(
            classification=RiskClassification.SAFE,
            blast_radius=BlastRadius.LOW,
            confidence_score=0.95,
        )
        assert assessment.classification == RiskClassification.SAFE
        assert assessment.policy_violations == []

    def test_confidence_score_bounds(self):
        """Confidence score should be between 0.0 and 1.0."""
        with pytest.raises(ValidationError):
            RiskAssessment(
                classification=RiskClassification.SAFE,
                blast_radius=BlastRadius.LOW,
                confidence_score=1.5,
            )

        with pytest.raises(ValidationError):
            RiskAssessment(
                classification=RiskClassification.SAFE,
                blast_radius=BlastRadius.LOW,
                confidence_score=-0.1,
            )


class TestEnums:
    """Test enum values."""

    def test_risk_classification_values(self):
        """RiskClassification should have SAFE, CANARY, HOLD."""
        assert RiskClassification.SAFE.value == "SAFE"
        assert RiskClassification.CANARY.value == "CANARY"
        assert RiskClassification.HOLD.value == "HOLD"

    def test_severity_values(self):
        """Severity should have all expected levels."""
        assert len(Severity) == 5
        assert Severity.CRITICAL.value == "Critical"

    def test_environment_values(self):
        """Environment should have Development, Staging, Production."""
        assert len(Environment) == 3
