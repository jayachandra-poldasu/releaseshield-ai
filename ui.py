"""
ReleaseShield AI — Streamlit Dashboard.

Provides a rich UI for:
- 📊 Dashboard: Service map overview, criticality distribution, recent incidents
- 🔍 Analysis: Run release risk analysis with policy engine + AI
- 📜 History: Incident timeline per service
"""

import streamlit as st
import requests
import json
import pandas as pd
from datetime import datetime

# ── Page Config ──────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="ReleaseShield AI | Risk Analysis Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ───────────────────────────────────────────────────────────────

st.markdown("""
<style>
    /* Dark theme overrides */
    .main { background-color: #0e1117; }
    
    /* Code editor styling */
    .stTextArea textarea {
        font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
        font-size: 13px;
        color: #e6e6e6;
        background-color: #1a1c23;
        border: 1px solid #2d3139;
        border-radius: 8px;
    }
    
    /* Metric cards */
    div[data-testid="metric-container"] {
        background-color: #1a1c23;
        border: 1px solid #2d3139;
        border-radius: 12px;
        padding: 16px;
    }
    
    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #0a0d12;
        border-right: 1px solid #1e2128;
    }
    
    /* Success/Warning/Error boxes */
    .stSuccess { border-radius: 8px; }
    .stWarning { border-radius: 8px; }
    .stError { border-radius: 8px; }
    
    /* Table styling */
    .dataframe { border-radius: 8px; overflow: hidden; }
    
    /* Custom header */
    .shield-header {
        background: linear-gradient(135deg, #1a1c23 0%, #0e1117 100%);
        border: 1px solid #2d3139;
        border-radius: 12px;
        padding: 20px 24px;
        margin-bottom: 24px;
    }
    
    .shield-header h1 {
        margin: 0;
        font-size: 28px;
    }
    
    .shield-header p {
        margin: 4px 0 0 0;
        color: #8b949e;
        font-size: 14px;
    }
    
    /* Violation card */
    .violation-card {
        background-color: #1a1c23;
        border-left: 4px solid;
        border-radius: 4px;
        padding: 12px 16px;
        margin-bottom: 8px;
    }
    
    .violation-critical { border-left-color: #f85149; }
    .violation-high { border-left-color: #d29922; }
    .violation-medium { border-left-color: #58a6ff; }
    .violation-low { border-left-color: #8b949e; }
</style>
""", unsafe_allow_html=True)


# ── Constants ────────────────────────────────────────────────────────────────

API_BASE_URL = "http://127.0.0.1:8000"

# Sample Terraform snippets (imported inline to avoid dependency on app package)
SAMPLE_SAFE = """# Safe change: Adding metadata labels to existing compute instance
resource "google_compute_instance" "api_server" {
  name         = "api-server-prod"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  labels = {
    environment = "production"
    team        = "platform"
    service     = "auth-service"
    cost_center = "engineering"
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
}"""

SAMPLE_RISKY = """# Risky: Opens firewall, public cluster, no encryption, public IAM
resource "google_compute_firewall" "allow_all_ingress" {
  name    = "allow-all-ingress"
  network = google_compute_network.vpc.self_link

  allow {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
  direction     = "INGRESS"
}

resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"
  deletion_protection = false

  node_pool {
    name       = "default-pool"
    node_count = 3
  }
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
}"""


# ── Helper Functions ─────────────────────────────────────────────────────────

def check_api_health() -> dict | None:
    """Check if the backend API is running."""
    try:
        resp = requests.get(f"{API_BASE_URL}/health", timeout=3)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def load_services() -> list[dict]:
    """Load services from the API."""
    try:
        resp = requests.get(f"{API_BASE_URL}/services", timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    # Fallback: load directly from file
    try:
        with open("data/service_map.json", "r") as f:
            data = json.load(f)
            return [
                {"name": k, **v} for k, v in data.items()
            ]
    except Exception:
        return []


def load_incidents(service_name: str = None) -> list[dict]:
    """Load incidents from the API or file."""
    try:
        if service_name:
            resp = requests.get(f"{API_BASE_URL}/history/{service_name}", timeout=5)
            if resp.status_code == 200:
                return resp.json().get("incidents", [])
        else:
            with open("data/incident_history.json", "r") as f:
                return json.load(f)
    except Exception:
        try:
            with open("data/incident_history.json", "r") as f:
                incidents = json.load(f)
                if service_name:
                    return [i for i in incidents if i.get("service") == service_name]
                return incidents
        except Exception:
            return []


def severity_color(severity: str) -> str:
    """Map severity to a display color."""
    colors = {
        "Critical": "🔴",
        "High": "🟠",
        "Medium": "🟡",
        "Low": "🔵",
        "Info": "⚪",
    }
    return colors.get(severity, "⚪")


# ── Sidebar ──────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🛡️ ReleaseShield AI")
    st.caption("Infrastructure Governance Platform")
    st.divider()

    # Navigation
    page = st.radio(
        "Navigation",
        ["📊 Dashboard", "🔍 Risk Analysis", "📜 Incident History"],
        label_visibility="collapsed",
    )

    st.divider()

    # API Status
    health = check_api_health()
    if health:
        st.success(f"✅ API Online (v{health.get('version', '?')})")
        ai_status = "🟢 Connected" if health.get("ai_available") else "🟡 Fallback Mode"
        st.info(f"AI Backend: {health.get('ai_backend', 'unknown')}\nStatus: {ai_status}")
    else:
        st.error("❌ API Offline")
        st.caption("Start with: `uvicorn app.main:app --reload`")

    st.divider()
    st.caption(f"© {datetime.now().year} ReleaseShield AI")


# ── Page: Dashboard ──────────────────────────────────────────────────────────

if page == "📊 Dashboard":
    st.markdown("""
    <div class="shield-header">
        <h1>🛡️ ReleaseShield AI</h1>
        <p>AI-Powered Infrastructure Governance & Safety Gate</p>
    </div>
    """, unsafe_allow_html=True)

    services = load_services()
    incidents = load_incidents()

    # Metrics Row
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Services", len(services))
    with col2:
        critical_count = sum(1 for s in services if s.get("criticality") == "Critical")
        st.metric("Critical Services", critical_count)
    with col3:
        st.metric("Total Incidents", len(incidents))
    with col4:
        if incidents:
            avg_mttr = sum(i.get("mttr_hours", 0) for i in incidents) / len(incidents)
            st.metric("Avg MTTR", f"{avg_mttr:.1f}h")
        else:
            st.metric("Avg MTTR", "N/A")

    st.divider()

    # Two-column layout
    left_col, right_col = st.columns([1.2, 1])

    with left_col:
        st.subheader("🗺️ Service Map")
        if services:
            df = pd.DataFrame(services)
            display_cols = ["name", "criticality", "owner", "team", "sla_tier"]
            available_cols = [c for c in display_cols if c in df.columns]
            st.dataframe(
                df[available_cols],
                use_container_width=True,
                hide_index=True,
                column_config={
                    "name": st.column_config.TextColumn("Service", width="medium"),
                    "criticality": st.column_config.TextColumn("Criticality", width="small"),
                    "owner": st.column_config.TextColumn("Owner", width="medium"),
                    "team": st.column_config.TextColumn("Team", width="medium"),
                    "sla_tier": st.column_config.TextColumn("SLA Tier", width="medium"),
                },
            )
        else:
            st.info("No services loaded. Ensure data/service_map.json exists.")

    with right_col:
        st.subheader("📈 Criticality Distribution")
        if services:
            crit_counts = {}
            for s in services:
                c = s.get("criticality", "Unknown")
                crit_counts[c] = crit_counts.get(c, 0) + 1
            crit_df = pd.DataFrame(
                list(crit_counts.items()),
                columns=["Criticality", "Count"]
            )
            st.bar_chart(crit_df.set_index("Criticality"))
        else:
            st.info("No data available.")

    st.divider()

    # Recent Incidents
    st.subheader("🔥 Recent Incidents")
    if incidents:
        sorted_incidents = sorted(
            incidents,
            key=lambda x: x.get("date", ""),
            reverse=True,
        )[:5]

        for inc in sorted_incidents:
            sev_icon = severity_color(inc.get("severity", ""))
            with st.expander(
                f"{sev_icon} [{inc.get('date', 'N/A')}] "
                f"{inc.get('service', 'unknown')} — {inc.get('issue', '')}"
            ):
                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown(f"**Root Cause:** {inc.get('root_cause', 'N/A')}")
                    st.markdown(f"**Resolution:** {inc.get('resolution', 'N/A')}")
                with col_b:
                    st.markdown(f"**Severity:** {inc.get('severity', 'N/A')}")
                    st.markdown(f"**MTTR:** {inc.get('mttr_hours', 'N/A')} hours")
    else:
        st.info("No incidents recorded.")


# ── Page: Risk Analysis ──────────────────────────────────────────────────────

elif page == "🔍 Risk Analysis":
    st.markdown("""
    <div class="shield-header">
        <h1>🔍 Release Risk Analysis</h1>
        <p>Evaluate infrastructure changes against enterprise security policies</p>
    </div>
    """, unsafe_allow_html=True)

    services = load_services()
    service_names = [s["name"] for s in services] if services else ["auth-service"]

    # Context Configuration
    ctx_col1, ctx_col2, ctx_col3 = st.columns(3)

    with ctx_col1:
        svc = st.selectbox("🎯 Target Service", service_names)
    with ctx_col2:
        env = st.selectbox("🌍 Environment", ["Development", "Staging", "Production"])
    with ctx_col3:
        dry_run = st.checkbox("🧪 Policy-Only Mode (skip AI)", value=False)

    # Show service context
    selected_svc = next((s for s in services if s["name"] == svc), {})
    if selected_svc:
        info_col1, info_col2, info_col3 = st.columns(3)
        with info_col1:
            st.info(f"**Criticality:** {selected_svc.get('criticality', 'N/A')}")
        with info_col2:
            deps = selected_svc.get("dependencies", [])
            st.info(f"**Dependencies:** {', '.join(deps) if deps else 'None'}")
        with info_col3:
            st.info(f"**Owner:** {selected_svc.get('owner', 'N/A')}")

    st.divider()

    # Sample Terraform loader
    st.subheader("🛠️ Proposed Infrastructure Changes")

    sample_col1, sample_col2, sample_col3 = st.columns(3)
    with sample_col1:
        if st.button("📋 Load Safe Example", use_container_width=True):
            st.session_state["tf_code"] = SAMPLE_SAFE
    with sample_col2:
        if st.button("⚠️ Load Risky Example", use_container_width=True):
            st.session_state["tf_code"] = SAMPLE_RISKY
    with sample_col3:
        if st.button("🗑️ Clear", use_container_width=True):
            st.session_state["tf_code"] = ""

    tf_code = st.text_area(
        "Paste Terraform Plan (HCL):",
        value=st.session_state.get("tf_code", ""),
        height=300,
        placeholder='resource "google_compute_instance" "api" { ... }',
    )

    # Execute Analysis
    st.divider()
    analyze_btn = st.button("🚀 Evaluate Release Risk", type="primary", use_container_width=True)

    if analyze_btn:
        if not tf_code.strip():
            st.error("❌ No infrastructure changes provided. Paste your Terraform plan or load a sample.")
        elif not health:
            st.error("❌ API is offline. Start the backend with: `uvicorn app.main:app --reload`")
        else:
            with st.spinner("🔍 Analyzing blast radius, policy violations, and historical patterns..."):
                try:
                    payload = {
                        "service_name": svc,
                        "environment": env,
                        "terraform_code": tf_code,
                        "dry_run": dry_run,
                    }
                    response = requests.post(
                        f"{API_BASE_URL}/analyze",
                        json=payload,
                        timeout=180,
                    )

                    if response.status_code == 200:
                        result = response.json()

                        # ── Classification Banner ──
                        classification = result.get("classification", "SAFE")
                        if classification == "HOLD":
                            st.error(f"🚨 CLASSIFICATION: **HOLD RELEASE** | Blast Radius: {result.get('blast_radius', 'N/A')} | Confidence: {result.get('confidence_score', 0):.0%}")
                        elif classification == "CANARY":
                            st.warning(f"⚠️ CLASSIFICATION: **CANARY ROLLOUT** | Blast Radius: {result.get('blast_radius', 'N/A')} | Confidence: {result.get('confidence_score', 0):.0%}")
                        else:
                            st.success(f"✅ CLASSIFICATION: **SAFE TO DEPLOY** | Blast Radius: {result.get('blast_radius', 'N/A')} | Confidence: {result.get('confidence_score', 0):.0%}")

                        # ── Metrics ──
                        m1, m2, m3, m4 = st.columns(4)
                        violations = result.get("policy_violations", [])
                        incidents = result.get("matched_incidents", [])

                        with m1:
                            st.metric("Policy Violations", len(violations))
                        with m2:
                            critical_v = sum(1 for v in violations if v.get("severity") == "Critical")
                            st.metric("Critical Findings", critical_v)
                        with m3:
                            st.metric("Incident Matches", len(incidents))
                        with m4:
                            st.metric("Confidence", f"{result.get('confidence_score', 0):.0%}")

                        st.divider()

                        # ── Policy Violations ──
                        if violations:
                            st.subheader("🔒 Policy Violations")
                            for v in violations:
                                sev = v.get("severity", "Info")
                                sev_class = sev.lower()
                                icon = severity_color(sev)
                                with st.expander(
                                    f"{icon} [{v.get('rule_id')}] {v.get('rule_name')} — {sev}"
                                ):
                                    st.markdown(f"**Description:** {v.get('message', '')}")
                                    if v.get("line_hint"):
                                        st.code(v["line_hint"], language="hcl")
                            st.divider()

                        # ── Matched Incidents ──
                        if incidents:
                            st.subheader("⚠️ Repeat Failure Pattern Detected")
                            for inc in incidents:
                                st.warning(
                                    f"**[{inc.get('date', 'N/A')}]** {inc.get('issue', '')}\n\n"
                                    f"Root Cause: {inc.get('root_cause', 'N/A')} | "
                                    f"MTTR: {inc.get('mttr_hours', 'N/A')}h"
                                )
                            st.divider()

                        # ── Rollout Guidance ──
                        if result.get("rollout_guidance"):
                            st.subheader("📋 Rollout Guidance")
                            st.info(result["rollout_guidance"])
                            st.divider()

                        # ── AI Analysis ──
                        if result.get("ai_analysis"):
                            st.subheader("🤖 AI Risk Intelligence Report")
                            st.markdown(result["ai_analysis"])

                    elif response.status_code == 404:
                        st.error(f"Service not found: {response.json().get('detail', '')}")
                    else:
                        st.error(f"API Error ({response.status_code}): {response.text}")

                except requests.exceptions.ConnectionError:
                    st.error("❌ Connection failed. Ensure the API is running: `uvicorn app.main:app --reload`")
                except requests.exceptions.Timeout:
                    st.error("❌ Analysis timed out. The AI backend may be under heavy load.")
                except Exception as e:
                    st.error(f"❌ Unexpected error: {e}")


# ── Page: Incident History ───────────────────────────────────────────────────

elif page == "📜 Incident History":
    st.markdown("""
    <div class="shield-header">
        <h1>📜 Incident History</h1>
        <p>Historical incident timeline and pattern analysis</p>
    </div>
    """, unsafe_allow_html=True)

    services = load_services()
    service_names = ["All Services"] + [s["name"] for s in services]

    selected = st.selectbox("Filter by Service", service_names)

    if selected == "All Services":
        incidents = load_incidents()
    else:
        incidents = load_incidents(selected)

    if incidents:
        # Summary metrics
        m1, m2, m3 = st.columns(3)
        with m1:
            st.metric("Total Incidents", len(incidents))
        with m2:
            critical_count = sum(1 for i in incidents if i.get("severity") in ["Critical", "High"])
            st.metric("Critical/High", critical_count)
        with m3:
            avg_mttr = sum(i.get("mttr_hours", 0) for i in incidents) / max(len(incidents), 1)
            st.metric("Avg MTTR", f"{avg_mttr:.1f}h")

        st.divider()

        # Incident table
        df = pd.DataFrame(incidents)
        display_cols = ["date", "service", "issue", "severity", "root_cause", "mttr_hours"]
        available_cols = [c for c in display_cols if c in df.columns]
        if available_cols:
            df_display = df[available_cols].sort_values(
                by="date", ascending=False
            ) if "date" in available_cols else df[available_cols]

            st.dataframe(
                df_display,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "date": st.column_config.TextColumn("Date", width="small"),
                    "service": st.column_config.TextColumn("Service", width="medium"),
                    "issue": st.column_config.TextColumn("Issue", width="large"),
                    "severity": st.column_config.TextColumn("Severity", width="small"),
                    "root_cause": st.column_config.TextColumn("Root Cause", width="large"),
                    "mttr_hours": st.column_config.NumberColumn("MTTR (h)", width="small"),
                },
            )

        st.divider()

        # Detailed expandable view
        st.subheader("📋 Detailed View")
        sorted_incidents = sorted(incidents, key=lambda x: x.get("date", ""), reverse=True)
        for inc in sorted_incidents:
            sev_icon = severity_color(inc.get("severity", ""))
            with st.expander(
                f"{sev_icon} [{inc.get('date', 'N/A')}] "
                f"{inc.get('service', 'unknown')} — {inc.get('issue', '')}"
            ):
                detail_col1, detail_col2 = st.columns(2)
                with detail_col1:
                    st.markdown(f"**Service:** {inc.get('service', 'N/A')}")
                    st.markdown(f"**Severity:** {inc.get('severity', 'N/A')}")
                    st.markdown(f"**Date:** {inc.get('date', 'N/A')}")
                    st.markdown(f"**MTTR:** {inc.get('mttr_hours', 'N/A')} hours")
                with detail_col2:
                    st.markdown(f"**Root Cause:** {inc.get('root_cause', 'N/A')}")
                    st.markdown(f"**Resolution:** {inc.get('resolution', 'N/A')}")
    else:
        st.info("No incidents found for the selected service.")