"""
AI Engine — LLM integration for release risk analysis.

Provides AI-generated release summaries explaining likely impact, risk drivers,
and safer rollout guidance. Supports pluggable backends (Ollama for local
inference, OpenAI for cloud inference) with graceful fallback when no AI
backend is available.
"""

import logging

import requests

from app.config import AIBackend, Settings, get_settings
from app.models import (
    BlastRadius,
    IncidentMatch,
    PolicyViolation,
    RiskClassification,
)

logger = logging.getLogger(__name__)


def _build_system_prompt() -> str:
    """Construct the system-level prompt that defines the AI's role."""
    return (
        "You are a SENIOR RELEASE RISK ENGINEER at a large financial-services company. "
        "Your job is to evaluate infrastructure changes and produce concise, actionable "
        "risk assessments. Be specific about what makes a change risky or safe. "
        "Reference the organizational context (service criticality, dependencies, "
        "historical failures) in your analysis. Keep your response under 300 words."
    )


def _build_analysis_prompt(
    terraform_code: str,
    service_name: str,
    environment: str,
    service_context: dict,
    violations: list[PolicyViolation],
    matched_incidents: list[IncidentMatch],
    classification: RiskClassification,
    blast_radius: BlastRadius,
) -> str:
    """Construct the user-level analysis prompt with full context."""

    violation_text = "None detected." if not violations else "\n".join(
        f"  - [{v.rule_id}] {v.rule_name} ({v.severity.value}): {v.message}"
        for v in violations
    )

    incident_text = "No matching historical incidents." if not matched_incidents else "\n".join(
        f"  - [{inc.date}] {inc.issue} (Severity: {inc.severity}, "
        f"Root Cause: {inc.root_cause}, MTTR: {inc.mttr_hours}h)"
        for inc in matched_incidents
    )

    return f"""
DEPLOYMENT CONTEXT:
- Service: {service_name}
- Environment: {environment}
- Service Criticality: {service_context.get('criticality', 'Unknown')}
- Downstream Dependencies: {', '.join(service_context.get('dependencies', [])) or 'None'}
- Service Owner: {service_context.get('owner', 'Unknown')}
- SLA Tier: {service_context.get('sla_tier', 'Unknown')}

PROPOSED TERRAFORM CHANGES:
```hcl
{terraform_code[:3000]}
```

POLICY ENGINE FINDINGS:
{violation_text}

MATCHING HISTORICAL INCIDENTS:
{incident_text}

PRE-CLASSIFIED RISK:
- Classification: {classification.value}
- Blast Radius: {blast_radius.value}

INSTRUCTIONS:
1. Explain WHY this specific change is classified as [{classification.value}].
2. Identify the top risk drivers from both the code and the organizational context.
3. If historical incidents match, explain the repeat-failure pattern risk.
4. Provide ONE specific, actionable SRE safety recommendation.
5. Keep the analysis concise (under 250 words).

OUTPUT FORMAT:
**Risk Analysis:** <your analysis>
**Top Risk Drivers:** <bulleted list>
**Rollout Recommendation:** <specific guidance>
"""


def _call_ollama(prompt: str, system_prompt: str, settings: Settings) -> str:
    """Call the Ollama API for local LLM inference."""
    payload = {
        "model": settings.ollama_model,
        "prompt": prompt,
        "system": system_prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_predict": 500,
        },
    }

    response = requests.post(
        settings.ollama_url,
        json=payload,
        timeout=settings.ollama_timeout,
    )
    response.raise_for_status()
    return response.json().get("response", "")


def _call_openai(prompt: str, system_prompt: str, settings: Settings) -> str:
    """Call the OpenAI API for cloud LLM inference."""
    headers = {
        "Authorization": f"Bearer {settings.openai_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": settings.openai_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.3,
        "max_tokens": 600,
    }

    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers=headers,
        json=payload,
        timeout=settings.openai_timeout,
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


def analyze(
    terraform_code: str,
    service_name: str,
    environment: str,
    service_context: dict,
    violations: list[PolicyViolation],
    matched_incidents: list[IncidentMatch],
    classification: RiskClassification,
    blast_radius: BlastRadius,
    settings: Settings | None = None,
) -> str:
    """
    Run AI-powered analysis on the release change.

    Constructs a context-rich prompt and sends it to the configured AI backend.
    Returns the AI-generated analysis text, or a fallback message if AI is
    unavailable.

    Args:
        terraform_code: The proposed infrastructure changes.
        service_name: Target service identifier.
        environment: Target deployment environment.
        service_context: Service metadata (criticality, dependencies, etc.).
        violations: Policy violations detected by the policy engine.
        matched_incidents: Historical incidents matching the change pattern.
        classification: Pre-determined risk classification.
        blast_radius: Pre-determined blast radius.
        settings: Application settings (uses global settings if not provided).

    Returns:
        AI-generated risk analysis narrative string.
    """
    if settings is None:
        settings = get_settings()

    if settings.ai_backend == AIBackend.NONE:
        return _generate_fallback_analysis(
            classification, violations, matched_incidents, service_context
        )

    system_prompt = _build_system_prompt()
    user_prompt = _build_analysis_prompt(
        terraform_code=terraform_code,
        service_name=service_name,
        environment=environment,
        service_context=service_context,
        violations=violations,
        matched_incidents=matched_incidents,
        classification=classification,
        blast_radius=blast_radius,
    )

    try:
        if settings.ai_backend == AIBackend.OLLAMA:
            return _call_ollama(user_prompt, system_prompt, settings)
        elif settings.ai_backend == AIBackend.OPENAI:
            return _call_openai(user_prompt, system_prompt, settings)
        else:
            return _generate_fallback_analysis(
                classification, violations, matched_incidents, service_context
            )
    except requests.exceptions.ConnectionError:
        logger.warning("AI backend connection failed. Using fallback analysis.")
        return _generate_fallback_analysis(
            classification, violations, matched_incidents, service_context
        )
    except requests.exceptions.Timeout:
        logger.warning("AI backend timed out. Using fallback analysis.")
        return _generate_fallback_analysis(
            classification, violations, matched_incidents, service_context
        )
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return _generate_fallback_analysis(
            classification, violations, matched_incidents, service_context
        )


def _generate_fallback_analysis(
    classification: RiskClassification,
    violations: list[PolicyViolation],
    matched_incidents: list[IncidentMatch],
    service_context: dict,
) -> str:
    """
    Generate a structured analysis without AI when the LLM backend is unavailable.

    This ensures the tool is always useful, even without GPU/API access.
    """
    parts = [
        "**Risk Analysis (Policy Engine):**",
        f"Classification: **{classification.value}** based on deterministic policy evaluation.",
        "",
    ]

    if violations:
        parts.append(f"**Policy Violations ({len(violations)}):**")
        for v in violations:
            parts.append(f"- [{v.rule_id}] {v.rule_name} ({v.severity.value}): {v.message}")
        parts.append("")

    if matched_incidents:
        parts.append("**⚠️ Repeat Failure Pattern Detected:**")
        for inc in matched_incidents:
            parts.append(
                f"- {inc.issue} ({inc.date}) — Root cause: {inc.root_cause}. "
                f"MTTR: {inc.mttr_hours}h"
            )
        parts.append("")
        parts.append(
            "This change shares characteristics with past incidents on this service. "
            "Increased scrutiny is recommended."
        )
        parts.append("")

    criticality = service_context.get("criticality", "Unknown")
    deps = service_context.get("dependencies", [])
    if deps:
        parts.append(
            f"**Blast Radius Context:** This {criticality}-criticality service "
            f"has {len(deps)} downstream dependencies: {', '.join(deps)}."
        )
        parts.append("")

    parts.append(
        "*Note: This analysis was generated by the deterministic policy engine. "
        "Connect an AI backend (Ollama/OpenAI) for deeper contextual analysis.*"
    )

    return "\n".join(parts)


def check_ai_health(settings: Settings | None = None) -> bool:
    """Check if the configured AI backend is reachable."""
    if settings is None:
        settings = get_settings()

    if settings.ai_backend == AIBackend.NONE:
        return False

    try:
        if settings.ai_backend == AIBackend.OLLAMA:
            # Ollama health check — hit the base URL
            base_url = settings.ollama_url.replace("/api/generate", "")
            resp = requests.get(base_url, timeout=5)
            return resp.status_code == 200
        elif settings.ai_backend == AIBackend.OPENAI:
            # For OpenAI, just verify the key is set
            return bool(settings.openai_api_key)
    except Exception:
        return False

    return False
