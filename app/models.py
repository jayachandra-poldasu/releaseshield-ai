"""
Pydantic models for API request/response schemas.

Defines the data contracts for the ReleaseShield AI API, including
release requests, policy violations, risk assessments, and health checks.
"""

from enum import Enum
from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────────────────

class RiskClassification(str, Enum):
    """Release risk classification levels."""
    SAFE = "SAFE"
    CANARY = "CANARY"
    HOLD = "HOLD"


class BlastRadius(str, Enum):
    """Estimated blast radius of a change."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class Severity(str, Enum):
    """Policy violation severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Environment(str, Enum):
    """Deployment target environments."""
    DEVELOPMENT = "Development"
    STAGING = "Staging"
    PRODUCTION = "Production"


# ── Request Models ───────────────────────────────────────────────────────────

class ReleaseRequest(BaseModel):
    """Request payload for release risk analysis."""
    service_name: str = Field(
        ...,
        description="Target service from the service map",
        examples=["auth-service"],
    )
    environment: Environment = Field(
        ...,
        description="Target deployment environment",
        examples=["Production"],
    )
    terraform_code: str = Field(
        ...,
        min_length=1,
        description="Terraform plan or HCL code to evaluate",
    )
    dry_run: bool = Field(
        default=False,
        description="If true, skip AI analysis and return only policy engine results",
    )


# ── Response Models ──────────────────────────────────────────────────────────

class PolicyViolation(BaseModel):
    """A single policy violation detected by the policy engine."""
    rule_id: str = Field(..., description="Unique rule identifier", examples=["R001"])
    rule_name: str = Field(..., description="Human-readable rule name")
    severity: Severity = Field(..., description="Violation severity level")
    message: str = Field(..., description="Detailed violation description")
    line_hint: str = Field(
        default="",
        description="Snippet of the offending code or pattern detected",
    )


class IncidentMatch(BaseModel):
    """A historical incident that matches the current change pattern."""
    service: str
    issue: str
    severity: str
    date: str = ""
    root_cause: str = ""
    resolution: str = ""
    mttr_hours: float = 0.0


class RiskAssessment(BaseModel):
    """Complete risk assessment response from the analysis pipeline."""
    classification: RiskClassification = Field(
        ..., description="Overall risk classification"
    )
    blast_radius: BlastRadius = Field(
        ..., description="Estimated blast radius"
    )
    confidence_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence in the classification (0.0 to 1.0)",
    )
    policy_violations: list[PolicyViolation] = Field(
        default_factory=list,
        description="List of deterministic policy violations found",
    )
    matched_incidents: list[IncidentMatch] = Field(
        default_factory=list,
        description="Historical incidents matching the change pattern",
    )
    ai_analysis: str = Field(
        default="",
        description="AI-generated risk analysis narrative",
    )
    rollout_guidance: str = Field(
        default="",
        description="Recommended rollout strategy",
    )
    service_context: dict = Field(
        default_factory=dict,
        description="Service metadata context used for analysis",
    )


class HealthResponse(BaseModel):
    """API health check response."""
    status: str = "healthy"
    version: str
    ai_backend: str
    ai_available: bool


class ServiceInfo(BaseModel):
    """Service metadata from the service map."""
    name: str
    criticality: str
    dependencies: list[str]
    owner: str = ""
    team: str = ""
    sla_tier: str = ""
