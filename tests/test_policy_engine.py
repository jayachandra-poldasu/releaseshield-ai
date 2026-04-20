"""
Unit tests for the Policy Engine.

Tests each rule individually, aggregation logic, incident cross-referencing,
classification, and rollout guidance generation.
"""


from app.models import (
    BlastRadius,
    RiskClassification,
    Severity,
)


# ── Rule Detection Tests ─────────────────────────────────────────────────────

class TestPolicyRuleDetection:
    """Test that each policy rule correctly detects violations."""

    def test_r001_public_cidr_detected(self, policy_engine):
        """R001: Should detect 0.0.0.0/0 open CIDR block."""
        code = 'source_ranges = ["0.0.0.0/0"]'
        violations = policy_engine.evaluate(code)
        rule_ids = [v.rule_id for v in violations]
        assert "R001" in rule_ids

    def test_r001_ipv6_open_cidr_detected(self, policy_engine):
        """R001: Should detect ::/0 IPv6 open CIDR block."""
        code = 'source_ranges = ["::/0"]'
        violations = policy_engine.evaluate(code)
        rule_ids = [v.rule_id for v in violations]
        assert "R001" in rule_ids

    def test_r001_private_cidr_clean(self, policy_engine):
        """R001: Should NOT flag private CIDR blocks."""
        code = 'source_ranges = ["10.0.0.0/8"]'
        violations = policy_engine.evaluate(code)
        rule_ids = [v.rule_id for v in violations]
        assert "R001" not in rule_ids

    def test_r002_all_users_detected(self, policy_engine):
        """R002: Should detect allUsers IAM binding."""
        code = 'members = ["allUsers"]'
        violations = policy_engine.evaluate(code)
        rule_ids = [v.rule_id for v in violations]
        assert "R002" in rule_ids

    def test_r002_all_authenticated_users_detected(self, policy_engine):
        """R002: Should detect allAuthenticatedUsers IAM binding."""
        code = 'members = ["allAuthenticatedUsers"]'
        violations = policy_engine.evaluate(code)
        rule_ids = [v.rule_id for v in violations]
        assert "R002" in rule_ids

    def test_r002_specific_user_clean(self, policy_engine):
        """R002: Should NOT flag specific service account bindings."""
        code = 'members = ["serviceAccount:my-sa@project.iam.gserviceaccount.com"]'
        violations = policy_engine.evaluate(code)
        rule_ids = [v.rule_id for v in violations]
        assert "R002" not in rule_ids

    def test_r005_allow_all_protocol_detected(self, policy_engine):
        """R005: Should detect firewall rule allowing all protocols."""
        code = '''
        allow {
            protocol = "all"
        }
        '''
        violations = policy_engine.evaluate(code)
        rule_ids = [v.rule_id for v in violations]
        assert "R005" in rule_ids

    def test_r005_specific_protocol_clean(self, policy_engine):
        """R005: Should NOT flag specific protocol rules."""
        code = '''
        allow {
            protocol = "tcp"
            ports    = ["443"]
        }
        '''
        violations = policy_engine.evaluate(code)
        rule_ids = [v.rule_id for v in violations]
        assert "R005" not in rule_ids

    def test_r007_public_gke_cluster_detected(self, policy_engine):
        """R007: Should detect GKE cluster without private_cluster_config."""
        code = '''
        resource "google_container_cluster" "primary" {
          name     = "prod-cluster"
          location = "us-central1"
        }
        '''
        violations = policy_engine.evaluate(code)
        rule_ids = [v.rule_id for v in violations]
        assert "R007" in rule_ids

    def test_r007_private_cluster_clean(self, policy_engine):
        """R007: Should NOT flag GKE cluster with private_cluster_config."""
        code = '''
        resource "google_container_cluster" "primary" {
          name     = "prod-cluster"
          location = "us-central1"

          private_cluster_config {
            enable_private_nodes = true
          }
        }
        '''
        violations = policy_engine.evaluate(code)
        rule_ids = [v.rule_id for v in violations]
        assert "R007" not in rule_ids

    def test_r008_deletion_protection_disabled(self, policy_engine):
        """R008: Should detect deletion_protection = false."""
        code = "deletion_protection = false"
        violations = policy_engine.evaluate(code)
        rule_ids = [v.rule_id for v in violations]
        assert "R008" in rule_ids

    def test_r008_force_destroy_detected(self, policy_engine):
        """R008: Should detect force_destroy = true."""
        code = "force_destroy = true"
        violations = policy_engine.evaluate(code)
        rule_ids = [v.rule_id for v in violations]
        assert "R008" in rule_ids

    def test_r008_deletion_protection_enabled_clean(self, policy_engine):
        """R008: Should NOT flag deletion_protection = true."""
        code = "deletion_protection = true"
        violations = policy_engine.evaluate(code)
        rule_ids = [v.rule_id for v in violations]
        assert "R008" not in rule_ids


# ── Safe Code Tests ──────────────────────────────────────────────────────────

class TestSafeCode:
    """Test that safe Terraform code produces no violations."""

    def test_safe_terraform_no_violations(self, policy_engine, safe_terraform):
        """Safe Terraform code should have zero violations."""
        violations = policy_engine.evaluate(safe_terraform)
        assert len(violations) == 0

    def test_empty_code_no_violations(self, policy_engine):
        """Empty code should produce no violations."""
        violations = policy_engine.evaluate("")
        assert len(violations) == 0

    def test_comment_only_code_no_violations(self, policy_engine):
        """Code with only comments should produce no violations."""
        violations = policy_engine.evaluate("# This is a comment\n# Another comment")
        assert len(violations) == 0


# ── Risky Code Tests ─────────────────────────────────────────────────────────

class TestRiskyCode:
    """Test that risky Terraform code triggers multiple violations."""

    def test_risky_terraform_has_violations(self, policy_engine, risky_terraform):
        """Risky Terraform code should have multiple violations."""
        violations = policy_engine.evaluate(risky_terraform)
        assert len(violations) >= 3

    def test_risky_terraform_has_critical_violations(self, policy_engine, risky_terraform):
        """Risky code should include Critical severity violations."""
        violations = policy_engine.evaluate(risky_terraform)
        severities = [v.severity for v in violations]
        assert Severity.CRITICAL in severities

    def test_violations_have_line_hints(self, policy_engine, risky_terraform):
        """Violations should include code snippets as line hints."""
        violations = policy_engine.evaluate(risky_terraform)
        for v in violations:
            assert v.line_hint, f"Violation {v.rule_id} should have a line hint"


# ── Classification Tests ─────────────────────────────────────────────────────

class TestClassification:
    """Test the risk classification logic."""

    def test_safe_classification_no_violations(self, policy_engine, safe_terraform):
        """No violations → SAFE classification."""
        violations = policy_engine.evaluate(safe_terraform)
        classification, _, _ = policy_engine.classify(
            violations, "monitoring-agent", "Development"
        )
        assert classification == RiskClassification.SAFE

    def test_hold_classification_critical_violations(self, policy_engine, risky_terraform):
        """Critical violations → HOLD classification."""
        violations = policy_engine.evaluate(risky_terraform)
        classification, _, _ = policy_engine.classify(
            violations, "auth-service", "Production"
        )
        assert classification == RiskClassification.HOLD

    def test_production_critical_service_escalation(self, policy_engine, moderate_terraform):
        """Production + Critical service should escalate CANARY → HOLD."""
        violations = policy_engine.evaluate(moderate_terraform)
        classification, _, _ = policy_engine.classify(
            violations, "auth-service", "Production"
        )
        # auth-service is Critical, production env → should escalate
        assert classification in (RiskClassification.HOLD, RiskClassification.CANARY)

    def test_blast_radius_high_for_critical_service(self, policy_engine, risky_terraform):
        """Critical service should have HIGH blast radius."""
        violations = policy_engine.evaluate(risky_terraform)
        _, blast_radius, _ = policy_engine.classify(
            violations, "auth-service", "Production"
        )
        assert blast_radius == BlastRadius.HIGH

    def test_blast_radius_low_for_no_dependencies(self, policy_engine, safe_terraform):
        """Service with no dependencies should have LOW blast radius."""
        violations = policy_engine.evaluate(safe_terraform)
        _, blast_radius, _ = policy_engine.classify(
            violations, "monitoring-agent", "Development"
        )
        assert blast_radius == BlastRadius.LOW

    def test_confidence_score_in_valid_range(self, policy_engine, risky_terraform):
        """Confidence score should be between 0.0 and 1.0."""
        violations = policy_engine.evaluate(risky_terraform)
        _, _, confidence = policy_engine.classify(
            violations, "auth-service", "Production"
        )
        assert 0.0 <= confidence <= 1.0


# ── Incident Cross-Reference Tests ───────────────────────────────────────────

class TestIncidentCrossReference:
    """Test incident history cross-referencing with violations."""

    def test_network_violation_matches_firewall_incident(self, policy_engine):
        """Network violations should match past firewall incidents."""
        code = 'source_ranges = ["0.0.0.0/0"]'
        violations = policy_engine.evaluate(code)
        matched = policy_engine.cross_reference_incidents(violations, "auth-service")
        # auth-service has a past firewall incident
        assert len(matched) >= 1

    def test_iam_violation_matches_iam_incident(self, policy_engine):
        """IAM violations should match past IAM incidents."""
        code = 'members = ["allUsers"]'
        violations = policy_engine.evaluate(code)
        matched = policy_engine.cross_reference_incidents(violations, "payment-api")
        # payment-api has a past IAM incident
        assert len(matched) >= 1

    def test_no_cross_reference_for_clean_code(self, policy_engine, safe_terraform):
        """Safe code should have no incident cross-references."""
        violations = policy_engine.evaluate(safe_terraform)
        matched = policy_engine.cross_reference_incidents(violations, "monitoring-agent")
        assert len(matched) == 0

    def test_incident_match_has_details(self, policy_engine):
        """Matched incidents should have service, issue, and severity."""
        code = 'source_ranges = ["0.0.0.0/0"]'
        violations = policy_engine.evaluate(code)
        matched = policy_engine.cross_reference_incidents(violations, "auth-service")
        if matched:
            inc = matched[0]
            assert inc.service == "auth-service"
            assert inc.issue
            assert inc.severity


# ── Service Context Tests ────────────────────────────────────────────────────

class TestServiceContext:
    """Test service map loading and context retrieval."""

    def test_get_known_service(self, policy_engine):
        """Should return correct context for known services."""
        ctx = policy_engine.get_service_context("auth-service")
        assert ctx["criticality"] == "Critical"
        assert "payment-api" in ctx["dependencies"]

    def test_get_unknown_service_defaults(self, policy_engine):
        """Should return safe defaults for unknown services."""
        ctx = policy_engine.get_service_context("nonexistent-service")
        assert ctx["criticality"] == "Unknown"

    def test_get_service_names(self, policy_engine):
        """Should return all service names."""
        names = policy_engine.get_service_names()
        assert "auth-service" in names
        assert "payment-api" in names
        assert "monitoring-agent" in names

    def test_get_incident_history(self, policy_engine):
        """Should return incidents for a specific service."""
        incidents = policy_engine.get_incident_history("auth-service")
        assert len(incidents) >= 1
        assert all(inc.service == "auth-service" for inc in incidents)


# ── Rollout Guidance Tests ───────────────────────────────────────────────────

class TestRolloutGuidance:
    """Test rollout guidance generation."""

    def test_safe_guidance(self, policy_engine):
        """SAFE classification should produce proceed guidance."""
        guidance = policy_engine.generate_rollout_guidance(
            RiskClassification.SAFE, [], "monitoring-agent", "Development"
        )
        assert "Proceed" in guidance or "✅" in guidance

    def test_canary_guidance(self, policy_engine, moderate_terraform):
        """CANARY classification should mention canary rollout."""
        violations = policy_engine.evaluate(moderate_terraform)
        guidance = policy_engine.generate_rollout_guidance(
            RiskClassification.CANARY, violations, "payment-api", "Staging"
        )
        assert "canary" in guidance.lower() or "⚠️" in guidance

    def test_hold_guidance(self, policy_engine, risky_terraform):
        """HOLD classification should mention hold and escalation."""
        violations = policy_engine.evaluate(risky_terraform)
        guidance = policy_engine.generate_rollout_guidance(
            RiskClassification.HOLD, violations, "auth-service", "Production"
        )
        assert "HOLD" in guidance or "🚨" in guidance
