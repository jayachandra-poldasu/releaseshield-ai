"""Shared test fixtures for ReleaseShield AI test suite."""

import json
import os
import tempfile

import pytest

from app.config import Settings, AIBackend
from app.policy_engine import PolicyEngine


@pytest.fixture
def sample_service_map():
    """Sample service map data for testing."""
    return {
        "auth-service": {
            "criticality": "Critical",
            "dependencies": ["payment-api", "user-dashboard", "gateway-proxy"],
            "owner": "Sarah Chen",
            "team": "Platform Engineering",
            "sla_tier": "Tier-1 (99.99%)",
        },
        "payment-api": {
            "criticality": "High",
            "dependencies": ["database-cluster-main"],
            "owner": "Marcus Rodriguez",
            "team": "Financial Services",
            "sla_tier": "Tier-1 (99.99%)",
        },
        "monitoring-agent": {
            "criticality": "Medium",
            "dependencies": [],
            "owner": "Aisha Patel",
            "team": "SRE / Observability",
            "sla_tier": "Tier-3 (99.9%)",
        },
    }


@pytest.fixture
def sample_incidents():
    """Sample incident history data for testing."""
    return [
        {
            "service": "auth-service",
            "issue": "Public endpoint exposed after firewall rule misconfiguration",
            "severity": "Critical",
            "date": "2025-08-22",
            "root_cause": "Firewall rule allowed 0.0.0.0/0 ingress during network migration",
            "resolution": "Reverted firewall rule, added policy-as-code gate",
            "mttr_hours": 1.2,
        },
        {
            "service": "auth-service",
            "issue": "Memory leak in JWT validation",
            "severity": "High",
            "date": "2025-11-15",
            "root_cause": "Unbounded token cache without TTL eviction",
            "resolution": "Added LRU cache with 10-minute TTL",
            "mttr_hours": 4.5,
        },
        {
            "service": "payment-api",
            "issue": "Data exposure via overly permissive IAM binding",
            "severity": "Critical",
            "date": "2025-06-18",
            "root_cause": "IAM binding granted allUsers read access to transaction logs",
            "resolution": "Removed public binding, rotated credentials",
            "mttr_hours": 0.8,
        },
    ]


@pytest.fixture
def test_data_dir(sample_service_map, sample_incidents):
    """Create a temporary data directory with test JSON files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write service map
        with open(os.path.join(tmpdir, "service_map.json"), "w") as f:
            json.dump(sample_service_map, f)

        # Write incidents
        with open(os.path.join(tmpdir, "incident_history.json"), "w") as f:
            json.dump(sample_incidents, f)

        yield tmpdir


@pytest.fixture
def policy_engine(test_data_dir):
    """PolicyEngine instance configured with test data."""
    return PolicyEngine(data_dir=test_data_dir)


@pytest.fixture
def settings_no_ai():
    """Settings configured with AI backend disabled."""
    return Settings(
        ai_backend=AIBackend.NONE,
        data_dir="/tmp/nonexistent",
    )


# ── Sample Terraform Code Fixtures ──────────────────────────────────────────

@pytest.fixture
def safe_terraform():
    """Terraform code that should pass all policy checks."""
    return """
resource "google_compute_instance" "api_server" {
  name         = "api-server-prod"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  labels = {
    environment = "production"
    team        = "platform"
    service     = "auth-service"
  }

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.vpc.self_link
    subnetwork = google_compute_subnetwork.private.self_link
  }

  metadata = {
    enable-oslogin = "TRUE"
  }
}
"""


@pytest.fixture
def risky_terraform():
    """Terraform code that should trigger multiple policy violations."""
    return """
resource "google_compute_firewall" "allow_all" {
  name    = "allow-all-ingress"
  network = google_compute_network.vpc.self_link

  allow {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"
  deletion_protection = false
}

resource "google_storage_bucket" "data_lake" {
  name     = "prod-data-lake"
  location = "US"
  force_destroy = true
}

resource "google_project_iam_binding" "public_access" {
  project = "my-project"
  role    = "roles/storage.objectViewer"
  members = ["allUsers"]
}
"""


@pytest.fixture
def moderate_terraform():
    """Terraform code with some medium-severity issues."""
    return """
resource "google_compute_instance" "web" {
  name         = "web-server"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  deletion_protection = false

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = google_compute_network.vpc.self_link
  }
}
"""
