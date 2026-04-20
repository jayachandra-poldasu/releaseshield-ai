"""
FastAPI application — ReleaseShield AI API.

Provides endpoints for release risk analysis, health checks,
service discovery, and incident history retrieval.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.ai_engine import analyze as ai_analyze, check_ai_health
from app.config import get_settings
from app.models import (
    HealthResponse,
    ReleaseRequest,
    RiskAssessment,
    ServiceInfo,
)
from app.policy_engine import PolicyEngine

logger = logging.getLogger(__name__)

# ── Application Lifespan ─────────────────────────────────────────────────────

_policy_engine: PolicyEngine | None = None


def get_policy_engine() -> PolicyEngine:
    """Return the global PolicyEngine instance, creating it if needed."""
    global _policy_engine
    if _policy_engine is None:
        settings = get_settings()
        _policy_engine = PolicyEngine(data_dir=settings.data_dir)
    return _policy_engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    # Startup: initialize the policy engine
    logger.info("🛡️ ReleaseShield AI starting up...")
    get_policy_engine()
    settings = get_settings()
    logger.info(f"   AI Backend: {settings.ai_backend.value}")
    logger.info(f"   Data Dir: {settings.data_dir}")
    yield
    # Shutdown
    logger.info("🛡️ ReleaseShield AI shutting down...")


# ── FastAPI App ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="ReleaseShield AI",
    description=(
        "AI-Powered Infrastructure Governance & Safety Gate. "
        "Evaluates Terraform plans against enterprise security policies "
        "using deterministic rule checks and AI-powered analysis."
    ),
    version=__version__,
    lifespan=lifespan,
)

# CORS middleware
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["System"])
def health_check():
    """Health check endpoint with AI backend status."""
    current_settings = get_settings()
    return HealthResponse(
        status="healthy",
        version=__version__,
        ai_backend=current_settings.ai_backend.value,
        ai_available=check_ai_health(current_settings),
    )


@app.get("/services", response_model=list[ServiceInfo], tags=["Services"])
def list_services():
    """List all registered services from the service map."""
    engine = get_policy_engine()
    services = []
    for name in engine.get_service_names():
        ctx = engine.get_service_context(name)
        services.append(ServiceInfo(
            name=name,
            criticality=ctx.get("criticality", "Unknown"),
            dependencies=ctx.get("dependencies", []),
            owner=ctx.get("owner", "Unknown"),
            team=ctx.get("team", "Unknown"),
            sla_tier=ctx.get("sla_tier", "Unclassified"),
        ))
    return services


@app.get("/history/{service_name}", tags=["Incidents"])
def get_incident_history(service_name: str):
    """Retrieve incident history for a specific service."""
    engine = get_policy_engine()
    if service_name not in engine.get_service_names():
        raise HTTPException(
            status_code=404,
            detail=f"Service '{service_name}' not found in service map.",
        )
    incidents = engine.get_incident_history(service_name)
    return {"service": service_name, "incidents": incidents}


@app.post("/analyze", response_model=RiskAssessment, tags=["Analysis"])
def analyze_release(request: ReleaseRequest):
    """
    Analyze a release for risk using the policy engine and AI.

    Pipeline:
    1. Run deterministic policy checks against the Terraform code.
    2. Cross-reference violations with historical incident data.
    3. Classify risk based on violations, service criticality, and environment.
    4. (Optional) Run AI analysis for narrative risk summary.
    5. Generate rollout guidance.
    """
    engine = get_policy_engine()

    # Validate service exists
    service_names = engine.get_service_names()
    if request.service_name not in service_names:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Service '{request.service_name}' not found. "
                f"Available services: {', '.join(service_names)}"
            ),
        )

    # 1. Policy Engine: Deterministic rule evaluation
    violations = engine.evaluate(request.terraform_code)

    # 2. Cross-reference with historical incidents
    matched_incidents = engine.cross_reference_incidents(
        violations, request.service_name
    )

    # 3. Classification
    classification, blast_radius, confidence = engine.classify(
        violations=violations,
        service_name=request.service_name,
        environment=request.environment.value,
    )

    # 4. Service context
    service_context = engine.get_service_context(request.service_name)

    # 5. AI Analysis (skip if dry_run)
    ai_analysis = ""
    if not request.dry_run:
        ai_analysis = ai_analyze(
            terraform_code=request.terraform_code,
            service_name=request.service_name,
            environment=request.environment.value,
            service_context=service_context,
            violations=violations,
            matched_incidents=matched_incidents,
            classification=classification,
            blast_radius=blast_radius,
        )

    # 6. Rollout Guidance
    rollout_guidance = engine.generate_rollout_guidance(
        classification=classification,
        violations=violations,
        service_name=request.service_name,
        environment=request.environment.value,
    )

    return RiskAssessment(
        classification=classification,
        blast_radius=blast_radius,
        confidence_score=confidence,
        policy_violations=violations,
        matched_incidents=matched_incidents,
        ai_analysis=ai_analysis,
        rollout_guidance=rollout_guidance,
        service_context=service_context,
    )
