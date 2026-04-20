"""
Utility functions for the ReleaseShield AI application.

Provides helper functions for data loading, text processing, and
sample Terraform snippets for demonstration purposes.
"""

import json


def load_json_file(filepath: str) -> dict | list:
    """Load and parse a JSON file, returning empty dict on failure."""
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def truncate_text(text: str, max_length: int = 200) -> str:
    """Truncate text to a maximum length with ellipsis."""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


# ── Sample Terraform Snippets for Demo ───────────────────────────────────────
# These are used in the Streamlit UI to let reviewers quickly test the tool.

SAMPLE_SAFE_TERRAFORM = """
# Safe change: Adding metadata labels to an existing compute instance
resource "google_compute_instance" "api_server" {
  name         = "api-server-prod"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  labels = {
    environment = "production"
    team        = "platform"
    service     = "auth-service"
    cost_center = "engineering"
    managed_by  = "terraform"
  }

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.vpc.self_link
    subnetwork = google_compute_subnetwork.private.self_link
    # No public IP - internal only
  }

  metadata = {
    enable-oslogin = "TRUE"
  }
}
""".strip()


SAMPLE_RISKY_TERRAFORM = """
# Risky change: Opening firewall to public internet with no encryption
resource "google_compute_firewall" "allow_all_ingress" {
  name    = "allow-all-ingress"
  network = google_compute_network.vpc.self_link

  allow {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
  direction     = "INGRESS"
  priority      = 100
}

resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"

  deletion_protection = false

  node_pool {
    name       = "default-pool"
    node_count = 3

    node_config {
      machine_type = "e2-standard-4"
    }
  }

  master_auth {
    client_certificate_config {
      issue_client_certificate = true
    }
  }
}

resource "google_storage_bucket" "data_lake" {
  name     = "prod-data-lake-unencrypted"
  location = "US"
  force_destroy = true
}

resource "google_project_iam_binding" "public_access" {
  project = "my-production-project"
  role    = "roles/storage.objectViewer"
  members = [
    "allUsers",
  ]
}
""".strip()


SAMPLE_MODERATE_TERRAFORM = """
# Moderate change: Scaling adjustments with some missing best practices
resource "google_compute_instance_group_manager" "api_pool" {
  name               = "api-pool-manager"
  base_instance_name = "api"
  zone               = "us-central1-a"
  target_size        = 5

  version {
    instance_template = google_compute_instance_template.api.self_link
  }

  named_port {
    name = "http"
    port = 8080
  }
}

resource "google_compute_instance_template" "api" {
  name_prefix  = "api-template-"
  machine_type = "e2-standard-2"

  disk {
    source_image = "debian-cloud/debian-11"
    auto_delete  = true
    boot         = true
    disk_size_gb = 50
  }

  network_interface {
    network    = google_compute_network.vpc.self_link
    subnetwork = google_compute_subnetwork.private.self_link
  }

  metadata = {
    enable-oslogin = "TRUE"
  }

  lifecycle {
    create_before_destroy = true
  }
}
""".strip()
