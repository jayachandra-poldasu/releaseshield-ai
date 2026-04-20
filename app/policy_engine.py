"""
Deterministic Policy Engine for infrastructure change analysis.

Evaluates Terraform/HCL code against a set of enterprise security policies
using pattern matching. This provides reliable, explainable results independent
of the AI backend — a key differentiator from pure LLM-wrapper approaches.

Policy rules are inspired by GCP/cloud security best practices:
- Private cluster enforcement
- IAM constraint validation
- Encryption requirements
- Network security rules
- Resource protection standards
"""

import json
import os
import re
from dataclasses import dataclass

from app.models import (
    BlastRadius,
    IncidentMatch,
    PolicyViolation,
    RiskClassification,
    Severity,
)


@dataclass
class PolicyRule:
    """Definition of a single policy check rule."""
    rule_id: str
    name: str
    description: str
    severity: Severity
    patterns: list[str]
    classification_impact: RiskClassification
    category: str = "security"


# ── Built-in Policy Rules ────────────────────────────────────────────────────

DEFAULT_RULES: list[PolicyRule] = [
    PolicyRule(
        rule_id="R001",
        name="Public IP / Open CIDR Block",
        description="Detects unrestricted network access via 0.0.0.0/0 CIDR blocks, "
                    "which exposes resources to the public internet.",
        severity=Severity.CRITICAL,
        patterns=[r"0\.0\.0\.0/0", r"source_ranges.*\*", r"::/0"],
        classification_impact=RiskClassification.HOLD,
        category="network",
    ),
    PolicyRule(
        rule_id="R002",
        name="Overly Permissive IAM Binding",
        description="Detects IAM bindings granting access to allUsers or "
                    "allAuthenticatedUsers, violating least-privilege principles.",
        severity=Severity.CRITICAL,
        patterns=[r"allUsers", r"allAuthenticatedUsers", r"roles/owner"],
        classification_impact=RiskClassification.HOLD,
        category="iam",
    ),
    PolicyRule(
        rule_id="R003",
        name="Missing Encryption Configuration",
        description="Storage or database resources should have encryption enabled. "
                    "Missing encryption config may expose data at rest.",
        severity=Severity.HIGH,
        patterns=[
            r"google_storage_bucket(?!.*encryption)",
            r"google_sql_database_instance(?!.*ip_configuration\s*\{[^}]*require_ssl\s*=\s*true)",
        ],
        classification_impact=RiskClassification.CANARY,
        category="encryption",
    ),
    PolicyRule(
        rule_id="R004",
        name="Missing Resource Labels/Tags",
        description="All cloud resources should have labels for cost allocation, "
                    "ownership tracking, and operational governance.",
        severity=Severity.MEDIUM,
        patterns=[
            r"resource\s+\"google_\w+\"(?![\s\S]*?labels\s*=)",
            r"resource\s+\"aws_\w+\"(?![\s\S]*?tags\s*=)",
        ],
        classification_impact=RiskClassification.CANARY,
        category="governance",
    ),
    PolicyRule(
        rule_id="R005",
        name="Overly Permissive Firewall Rule",
        description="Firewall rules allowing all protocols or all ports increase "
                    "attack surface significantly.",
        severity=Severity.CRITICAL,
        patterns=[
            r"allow\s*\{[^}]*protocol\s*=\s*\"all\"",
            r"allow\s*\{[^}]*ports\s*=\s*\[\"0-65535\"\]",
            r"ingress.*allow.*all",
        ],
        classification_impact=RiskClassification.HOLD,
        category="network",
    ),
    PolicyRule(
        rule_id="R006",
        name="Auto-Scaling Disabled on Node Pool",
        description="GKE node pools without autoscaling may fail to handle "
                    "traffic spikes, causing service degradation.",
        severity=Severity.MEDIUM,
        patterns=[
            r"node_pool(?![\s\S]*?autoscaling\s*\{)",
            r"autoscaling\s*\{[^}]*disabled\s*=\s*true",
        ],
        classification_impact=RiskClassification.CANARY,
        category="scaling",
    ),
    PolicyRule(
        rule_id="R007",
        name="Public GKE Cluster (Missing Private Config)",
        description="GKE clusters should use private_cluster_config to prevent "
                    "public endpoint exposure per enterprise security standards.",
        severity=Severity.CRITICAL,
        patterns=[
            r"google_container_cluster(?![\s\S]*?private_cluster_config\s*\{)",
            r"enable_private_nodes\s*=\s*false",
        ],
        classification_impact=RiskClassification.HOLD,
        category="network",
    ),
    PolicyRule(
        rule_id="R008",
        name="Deletion Protection Disabled",
        description="Critical resources should have deletion protection enabled "
                    "to prevent accidental data loss.",
        severity=Severity.HIGH,
        patterns=[
            r"deletion_protection\s*=\s*false",
            r"force_destroy\s*=\s*true",
        ],
        classification_impact=RiskClassification.CANARY,
        category="protection",
    ),
]


class PolicyEngine:
    """
    Evaluates Terraform code against enterprise security policies.

    The engine runs deterministic pattern-matching rules and cross-references
    results with historical incident data and service dependency metadata
    to produce an overall risk classification.
    """

    def __init__(
        self,
        rules: list[PolicyRule] | None = None,
        data_dir: str | None = None,
    ):
        self.rules = rules or DEFAULT_RULES
        self._data_dir = data_dir
        self._service_map: dict = {}
        self._incidents: list[dict] = []
        self._load_data()

    def _load_data(self) -> None:
        """Load service map and incident history from JSON files."""
        if not self._data_dir:
            return

        service_map_path = os.path.join(self._data_dir, "service_map.json")
        incidents_path = os.path.join(self._data_dir, "incident_history.json")

        if os.path.exists(service_map_path):
            with open(service_map_path, "r") as f:
                self._service_map = json.load(f)

        if os.path.exists(incidents_path):
            with open(incidents_path, "r") as f:
                self._incidents = json.load(f)

    def get_service_context(self, service_name: str) -> dict:
        """Retrieve service metadata from the service map."""
        return self._service_map.get(service_name, {
            "criticality": "Unknown",
            "dependencies": [],
            "owner": "Unknown",
            "team": "Unknown",
            "sla_tier": "Unclassified",
        })

    def get_service_names(self) -> list[str]:
        """Return list of all registered service names."""
        return list(self._service_map.keys())

    def get_incident_history(self, service_name: str) -> list[IncidentMatch]:
        """Retrieve historical incidents for a given service."""
        matches = []
        for inc in self._incidents:
            if inc.get("service") == service_name:
                matches.append(IncidentMatch(
                    service=inc["service"],
                    issue=inc.get("issue", ""),
                    severity=inc.get("severity", "Unknown"),
                    date=inc.get("date", ""),
                    root_cause=inc.get("root_cause", ""),
                    resolution=inc.get("resolution", ""),
                    mttr_hours=inc.get("mttr_hours", 0.0),
                ))
        return matches

    def evaluate(self, terraform_code: str) -> list[PolicyViolation]:
        """
        Run all policy rules against the provided Terraform code.

        Returns a list of PolicyViolation objects for each rule that matched.
        """
        violations: list[PolicyViolation] = []

        for rule in self.rules:
            for pattern in rule.patterns:
                try:
                    match = re.search(pattern, terraform_code, re.IGNORECASE | re.DOTALL)
                    if match:
                        # Extract a snippet around the match for context
                        start = max(0, match.start() - 30)
                        end = min(len(terraform_code), match.end() + 30)
                        snippet = terraform_code[start:end].strip()

                        violations.append(PolicyViolation(
                            rule_id=rule.rule_id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            message=rule.description,
                            line_hint=snippet,
                        ))
                        break  # One match per rule is sufficient
                except re.error:
                    # Skip malformed regex patterns gracefully
                    continue

        return violations

    def cross_reference_incidents(
        self,
        violations: list[PolicyViolation],
        service_name: str,
    ) -> list[IncidentMatch]:
        """
        Cross-reference policy violations with historical incidents.

        If a violation's category matches a past incident's root cause keywords,
        flag it as a repeat failure pattern — critical for risk escalation.
        """
        past_incidents = self.get_incident_history(service_name)
        matched: list[IncidentMatch] = []

        # Build keyword map from violation categories
        violation_keywords = set()
        for v in violations:
            rule = next((r for r in self.rules if r.rule_id == v.rule_id), None)
            if rule:
                violation_keywords.add(rule.category)
                violation_keywords.update(v.message.lower().split())

        for incident in past_incidents:
            incident_text = (
                f"{incident.issue} {incident.root_cause} {incident.resolution}"
            ).lower()
            if any(kw in incident_text for kw in violation_keywords):
                matched.append(incident)

        return matched

    def classify(
        self,
        violations: list[PolicyViolation],
        service_name: str,
        environment: str,
    ) -> tuple[RiskClassification, BlastRadius, float]:
        """
        Determine overall risk classification based on violations, service
        criticality, environment, and dependency relationships.

        Returns (classification, blast_radius, confidence_score).
        """
        svc_ctx = self.get_service_context(service_name)
        criticality = svc_ctx.get("criticality", "Low")
        dependencies = svc_ctx.get("dependencies", [])

        # --- Classification Logic ---
        if not violations:
            classification = RiskClassification.SAFE
            confidence = 0.95
        else:
            severity_counts = {s: 0 for s in Severity}
            for v in violations:
                severity_counts[v.severity] += 1

            if severity_counts[Severity.CRITICAL] > 0:
                classification = RiskClassification.HOLD
                confidence = 0.90
            elif severity_counts[Severity.HIGH] > 0:
                classification = RiskClassification.CANARY
                confidence = 0.85
            else:
                classification = RiskClassification.CANARY
                confidence = 0.80

        # --- Escalation: Production + Critical service → always stricter ---
        if environment == "Production" and criticality == "Critical":
            if classification == RiskClassification.CANARY:
                classification = RiskClassification.HOLD
                confidence = min(confidence + 0.05, 1.0)
            confidence = min(confidence + 0.05, 1.0)

        # --- Escalation: Repeat failure pattern ---
        matched_incidents = self.cross_reference_incidents(violations, service_name)
        if matched_incidents:
            if classification == RiskClassification.CANARY:
                classification = RiskClassification.HOLD
            confidence = min(confidence + 0.05, 1.0)

        # --- Blast Radius ---
        dep_count = len(dependencies)
        if dep_count >= 3 or criticality == "Critical":
            blast_radius = BlastRadius.HIGH
        elif dep_count >= 1 or criticality == "High":
            blast_radius = BlastRadius.MEDIUM
        else:
            blast_radius = BlastRadius.LOW

        return classification, blast_radius, round(confidence, 2)

    def generate_rollout_guidance(
        self,
        classification: RiskClassification,
        violations: list[PolicyViolation],
        service_name: str,
        environment: str,
    ) -> str:
        """Generate deterministic rollout guidance based on classification."""
        svc_ctx = self.get_service_context(service_name)

        if classification == RiskClassification.SAFE:
            return (
                f"✅ Proceed with standard deployment to {environment}. "
                f"No policy violations detected. Follow normal change management process."
            )

        if classification == RiskClassification.CANARY:
            guidance_parts = [
                f"⚠️ Deploy to {environment} using a canary rollout strategy.",
                "Route ≤5% of traffic initially, monitor for 30 minutes.",
            ]
            if svc_ctx.get("dependencies"):
                deps = ", ".join(svc_ctx["dependencies"])
                guidance_parts.append(
                    f"Verify downstream dependencies ({deps}) are unaffected."
                )
            guidance_parts.append(
                f"Address {len(violations)} policy finding(s) before full rollout."
            )
            return " ".join(guidance_parts)

        # HOLD
        violation_summary = "; ".join(
            f"[{v.rule_id}] {v.rule_name}" for v in violations[:3]
        )
        return (
            f"🚨 HOLD RELEASE — Do not deploy to {environment}. "
            f"Critical policy violations detected: {violation_summary}. "
            f"Escalate to the service owner ({svc_ctx.get('owner', 'N/A')}) "
            f"and resolve all Critical/High findings before re-evaluation."
        )
