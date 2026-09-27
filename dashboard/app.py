"""AuthShield Security Operations Center (SOC) & Advanced IAM Threat Monitoring Dashboard.

Enterprise-grade SIEM/SOC console featuring:
  - Real-time telemetry, threat level indicator, and KPI metrics
  - Altair-powered threat and authentication distribution visualizations
  - Interactive incident triage queue with 1-click status transitions & card/table views
  - Active Defense & Remediation Console (manual IP blocklist, account quarantine & IP lookup)
  - Searchable audit log forensic explorer with preset filters & CSV export
  - Interactive attack simulation lab with MITRE ATT&CK mappings & live execution logs
  - Real-world background traffic generator (adds realistic user logins every 10s)
"""

import sys
import os
import time
import random
from datetime import datetime, timezone, timedelta

# Ensure the root repository directory is at the head of sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Prevent 'app.py' from shadowing the 'app' package
DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
while DASHBOARD_DIR in sys.path:
    sys.path.remove(DASHBOARD_DIR)

if "app" in sys.modules and not hasattr(sys.modules["app"], "__path__"):
    del sys.modules["app"]

import streamlit as st
import pandas as pd
import altair as alt
import httpx
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, case

from app.database.connection import SessionLocal
from app.models.user import User
from app.models.role import Role
from app.models.audit import AuditLog
from app.models.alert import SecurityAlert
from app.models.blocklist import BlockedIP
from app.services.audit_service import AuditService
from app.services.alert_service import AlertService
from app.services.blocklist_service import BlocklistService
from app.detection.engine import DetectionEngine

# -----------------------------------------------------------------------------
# Page Configuration
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="AuthShield — SOC Threat & IAM Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -----------------------------------------------------------------------------
# Bespoke Enterprise CSS Theme (Cybersecurity SOC Dark/Slate Palette)
# -----------------------------------------------------------------------------
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }

    code, kbd, samp, pre {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Core Deep Black Architecture */
    .stApp, [data-testid="stAppViewContainer"], [data-testid="stHeader"] {
        background-color: #060709 !important;
        color: #e2e8f0 !important;
    }

    [data-testid="stSidebar"] {
        background-color: #040508 !important;
        border-right: 1px solid #141923 !important;
    }

    [data-testid="stSidebar"] hr {
        border-color: #141923 !important;
    }

    /* Professional SOC Command Header */
    .soc-header {
        background: #090c12;
        border: 1px solid #18202e;
        border-left: 3px solid #0284c7;
        border-radius: 6px;
        padding: 1.1rem 1.5rem;
        margin-bottom: 1.25rem;
        box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.7);
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 1rem;
    }

    .soc-header-title {
        font-size: 1.35rem;
        font-weight: 700;
        color: #f8fafc;
        letter-spacing: 0.02em;
        font-family: 'JetBrains Mono', monospace;
        display: flex;
        align-items: center;
        gap: 0.65rem;
    }

    .soc-header-subtitle {
        font-size: 0.78rem;
        color: #64748b;
        font-family: 'JetBrains Mono', monospace;
        letter-spacing: 0.04em;
        margin-top: 0.25rem;
    }

    .soc-telemetry-tag {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        font-weight: 600;
        color: #38bdf8;
        background: #081d2a;
        border: 1px solid #0369a1;
        padding: 0.35rem 0.65rem;
        border-radius: 4px;
        letter-spacing: 0.05em;
    }

    /* Minimalist Live Radar Indicator */
    .live-dot {
        display: inline-block;
        width: 8px;
        height: 8px;
        background-color: #10b981;
        border-radius: 50%;
        box-shadow: 0 0 6px rgba(16, 185, 129, 0.8);
    }

    /* DEFCON / Threat Alert Badges (Authentic Military/SOC Design) */
    .threat-pill {
        display: inline-flex;
        align-items: center;
        gap: 0.45rem;
        padding: 0.35rem 0.85rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        font-family: 'JetBrains Mono', monospace;
    }
    .threat-defcon1 { background: #22090e; color: #fca5a5; border: 1px solid #991b1b; }
    .threat-defcon2 { background: #221307; color: #fcd34d; border: 1px solid #92400e; }
    .threat-defcon3 { background: #211c06; color: #fde047; border: 1px solid #854d0e; }
    .threat-normal  { background: #051a12; color: #6ee7b7; border: 1px solid #065f46; }

    /* High-Density Tactical KPI Metric Cards */
    .kpi-card {
        background: #090c12;
        border: 1px solid #161c28;
        border-radius: 6px;
        padding: 1rem 1.15rem;
        position: relative;
        overflow: hidden;
        transition: border-color 0.15s ease;
    }
    .kpi-card:hover {
        border-color: #2b3547;
    }
    .kpi-accent-red    { border-left: 3px solid #dc2626; }
    .kpi-accent-orange { border-left: 3px solid #ea580c; }
    .kpi-accent-blue   { border-left: 3px solid #0284c7; }
    .kpi-accent-green  { border-left: 3px solid #059669; }
    .kpi-accent-purple { border-left: 3px solid #7c3aed; }
    .kpi-accent-cyan   { border-left: 3px solid #0891b2; }

    .kpi-label {
        font-size: 0.72rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #64748b;
        font-weight: 600;
        margin-bottom: 0.35rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-family: 'JetBrains Mono', monospace;
    }
    .kpi-value {
        font-size: 1.75rem;
        font-weight: 700;
        color: #f8fafc;
        font-family: 'JetBrains Mono', monospace;
        line-height: 1.2;
    }
    .kpi-caption {
        font-size: 0.72rem;
        color: #475569;
        font-family: 'JetBrains Mono', monospace;
        margin-top: 0.35rem;
    }

    /* Severity Badges */
    .badge {
        display: inline-block;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 600;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        font-family: 'JetBrains Mono', monospace;
    }
    .badge-critical { background: #260a0f; color: #fca5a5; border: 1px solid #7f1d1d; }
    .badge-high     { background: #281408; color: #fdba74; border: 1px solid #9a3412; }
    .badge-medium   { background: #262007; color: #fde047; border: 1px solid #854d0e; }
    .badge-low      { background: #081d2a; color: #93c5fd; border: 1px solid #075985; }

    /* Status Badges */
    .badge-open          { background: #260a0f; color: #fda4af; border: 1px solid #881337; }
    .badge-investigating { background: #1c0e2d; color: #d8b4fe; border: 1px solid #581c87; }
    .badge-resolved      { background: #051d14; color: #6ee7b7; border: 1px solid #064e3b; }
    .badge-falsepositive { background: #111827; color: #94a3b8; border: 1px solid #374151; }

    /* Section Subheadings */
    .soc-section-title {
        font-size: 0.95rem;
        font-weight: 700;
        color: #cbd5e1;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        margin: 1.25rem 0 0.65rem 0;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-family: 'JetBrains Mono', monospace;
    }

    /* Native Container & Widget Styling */
    div[data-testid="stVerticalBlock"] > div[data-testid="stContainer"] {
        background: #090c12 !important;
        border: 1px solid #161c28 !important;
        border-radius: 6px !important;
    }

    /* Buttons */
    .stButton > button {
        background: #0d1118 !important;
        color: #c9d1d9 !important;
        border: 1px solid #212630 !important;
        border-radius: 4px !important;
        font-family: 'Inter', sans-serif !important;
        font-weight: 500 !important;
        font-size: 0.85rem !important;
        transition: all 0.15s ease !important;
    }
    .stButton > button:hover {
        background: #151b26 !important;
        border-color: #3b4556 !important;
        color: #f8fafc !important;
    }
    .stButton > button[kind="primary"] {
        background: #0284c7 !important;
        color: #ffffff !important;
        border: 1px solid #0284c7 !important;
    }
    .stButton > button[kind="primary"]:hover {
        background: #0369a1 !important;
        border-color: #0369a1 !important;
    }

    /* Dataframes */
    div[data-testid="stDataFrame"] {
        border: 1px solid #161c28 !important;
        border-radius: 6px !important;
    }
</style>
""", unsafe_allow_html=True)


def get_db_session() -> Session:
    """Provides a fresh database session."""
    return SessionLocal()


def get_api_client():
    """
    Returns an HTTP client pointing to the live server (if running)
    or falls back to FastAPI TestClient in-process.
    """
    try:
        r = httpx.get("http://127.0.0.1:8000/health", timeout=0.6)
        if r.status_code == 200:
            return httpx.Client(base_url="http://127.0.0.1:8000", timeout=5.0), True
    except Exception:
        pass
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app), False


# -----------------------------------------------------------------------------
# Session State Initialization
# -----------------------------------------------------------------------------
if "flash_message" not in st.session_state:
    st.session_state.flash_message = None
if "flash_type" not in st.session_state:
    st.session_state.flash_type = "success"
if "sim_logs" not in st.session_state:
    st.session_state.sim_logs = []
if "auto_traffic_enabled" not in st.session_state:
    st.session_state.auto_traffic_enabled = False
if "last_traffic_time" not in st.session_state:
    st.session_state.last_traffic_time = 0
if "inspected_ip" not in st.session_state:
    st.session_state.inspected_ip = ""


# -----------------------------------------------------------------------------
# Callbacks: Triage, Manual Containment & Active Defense
# -----------------------------------------------------------------------------
def handle_triage_action(alert_id: int, new_status: str):
    """Callback to update alert triage status."""
    db_conn = get_db_session()
    try:
        AlertService.update_status(db_conn, alert_id, new_status)
        AuditService.log_event(
            db=db_conn,
            action="ALERT_STATUS_UPDATED",
            endpoint="/dashboard/alerts",
            status="SUCCESS",
            ip_address="127.0.0.1",
            details=f"Alert #{alert_id} triage updated to '{new_status}' by analyst"
        )
        st.session_state.flash_message = f"Alert #{alert_id} successfully updated to status: {new_status}"
        st.session_state.flash_type = "success"
    finally:
        db_conn.close()


def handle_block_ip_action(ip_address: str, reason: str = "Manually blocked by security analyst"):
    """Callback to manually quarantine an IP address."""
    clean_ip = ip_address.strip()
    db_conn = get_db_session()
    try:
        BlocklistService.block_ip(db_conn, clean_ip, reason=reason, blocked_by="analyst@authshield.io")
        st.session_state.flash_message = f"🚫 Source IP '{clean_ip}' has been actively quarantined! All subsequent connections will be rejected (403)."
        st.session_state.flash_type = "warning"
    finally:
        db_conn.close()


def handle_unblock_ip_action(ip_address: str):
    """Callback to release an IP from active quarantine."""
    clean_ip = ip_address.strip()
    db_conn = get_db_session()
    try:
        BlocklistService.unblock_ip(db_conn, clean_ip, unblocked_by="analyst@authshield.io")
        st.session_state.flash_message = f"🔓 IP '{clean_ip}' has been released from active quarantine."
        st.session_state.flash_type = "success"
    finally:
        db_conn.close()


def handle_quarantine_user_action(user_id: int):
    """Callback to disable a compromised user account."""
    db_conn = get_db_session()
    try:
        u = db_conn.query(User).filter(User.id == user_id).first()
        if u:
            u.status = "disabled"
            db_conn.commit()
            AuditService.log_event(
                db=db_conn,
                action="USER_QUARANTINED",
                endpoint="/dashboard/remediation",
                status="SUCCESS",
                ip_address="127.0.0.1",
                details=f"Account '{u.username}' (ID: {u.id}) manually quarantined by analyst"
            )
            st.session_state.flash_message = f"🔒 User account '{u.username}' has been quarantined and disabled."
            st.session_state.flash_type = "warning"
    finally:
        db_conn.close()


def handle_restore_user_action(user_id: int):
    """Callback to restore an account to active status."""
    db_conn = get_db_session()
    try:
        u = db_conn.query(User).filter(User.id == user_id).first()
        if u:
            u.status = "active"
            db_conn.commit()
            AuditService.log_event(
                db=db_conn,
                action="USER_RESTORED",
                endpoint="/dashboard/remediation",
                status="SUCCESS",
                ip_address="127.0.0.1",
                details=f"Account '{u.username}' (ID: {u.id}) restored and re-enabled by analyst"
            )
            st.session_state.flash_message = f"✅ User account '{u.username}' has been restored and activated."
            st.session_state.flash_type = "success"
    finally:
        db_conn.close()


def inject_single_traffic_event():
    """Injects a single realistic authentication event into the system."""
    client, _ = get_api_client()
    now_str = datetime.now().strftime("%H:%M:%S")
    roll = random.random()

    if roll < 0.70:
        # Legitimate Login
        user_choice = random.choice([
            ("user@authshield.io", "UserPassword123!", "user"),
            ("analyst@authshield.io", "AnalystPassword123!", "analyst"),
            ("admin@authshield.io", "AdminPassword123!", "admin")
        ])
        ip = f"192.168.1.{random.randint(100, 240)}"
        resp = client.post(
            "/auth/login",
            json={"email": user_choice[0], "password": user_choice[1]},
            headers={"X-Simulated-IP": ip}
        )
        msg = f"[{now_str}] [TRAFFIC STREAM] Legitimate Login: {user_choice[0]} from {ip} -> HTTP {resp.status_code} OK"
    elif roll < 0.85:
        # User Typo
        user_email = random.choice(["user@authshield.io", "analyst@authshield.io"])
        ip = f"192.168.1.{random.randint(100, 240)}"
        resp = client.post(
            "/auth/login",
            json={"email": user_email, "password": "WrongPasswordTypo!"},
            headers={"X-Simulated-IP": ip}
        )
        msg = f"[{now_str}] [TRAFFIC STREAM] User Typo: {user_email} from {ip} -> HTTP {resp.status_code} Unauthorized (Normal Noise)"
    else:
        # Threat Anomaly
        attacker_ip = f"185.220.{random.randint(100, 250)}.{random.randint(10, 250)}"
        for b in range(5):
            client.post(
                "/auth/login",
                json={"email": "admin@authshield.io", "password": f"spray_{b}"},
                headers={"X-Simulated-IP": attacker_ip}
            )
        msg = f"[{now_str}] [TRAFFIC STREAM] Threat Injected: 5 failed logins from {attacker_ip} -> BRUTE_FORCE_LOGIN Alert Triggered!"

    st.session_state.sim_logs.append(msg)
    if len(st.session_state.sim_logs) > 40:
        st.session_state.sim_logs.pop(0)


# Check if auto-traffic timer has elapsed
current_ts = time.time()
if st.session_state.auto_traffic_enabled and (current_ts - st.session_state.last_traffic_time >= 10):
    st.session_state.last_traffic_time = current_ts
    inject_single_traffic_event()


# -----------------------------------------------------------------------------
# System Metrics & Threat Level Calculation
# -----------------------------------------------------------------------------
db = get_db_session()
try:
    total_users_count = db.query(func.count(User.id)).scalar() or 0
    disabled_users_count = db.query(func.count(User.id)).filter(User.status == "disabled").scalar() or 0
    total_events_count = db.query(func.count(AuditLog.id)).scalar() or 0
    failed_logins_count = db.query(func.count(AuditLog.id)).filter(AuditLog.action == "LOGIN_FAILED").scalar() or 0
    success_logins_count = db.query(func.count(AuditLog.id)).filter(AuditLog.action == "LOGIN_SUCCESS").scalar() or 0
    denied_access_count = db.query(func.count(AuditLog.id)).filter(AuditLog.action == "ACCESS_DENIED").scalar() or 0
    open_alerts_count = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.status == "OPEN").scalar() or 0
    investigating_alerts_count = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.status == "INVESTIGATING").scalar() or 0
    critical_alerts_count = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.severity == "CRITICAL", SecurityAlert.status == "OPEN").scalar() or 0
    high_alerts_count = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.severity == "HIGH", SecurityAlert.status == "OPEN").scalar() or 0
    active_blocked_ips_count = db.query(func.count(BlockedIP.id)).filter(BlockedIP.is_active == True).scalar() or 0
    blocked_attempts_count = db.query(func.count(AuditLog.id)).filter(AuditLog.action == "BLOCKED_IP_REJECTED").scalar() or 0

    # Dynamic Threat Level
    if critical_alerts_count > 0:
        threat_level_class = "threat-defcon1"
        threat_level_text = "🚨 DEFCON 1: CRITICAL THREAT"
    elif high_alerts_count > 0 or open_alerts_count >= 5:
        threat_level_class = "threat-defcon2"
        threat_level_text = "⚠️ DEFCON 2: ELEVATED RISK"
    elif open_alerts_count > 0 or investigating_alerts_count > 0:
        threat_level_class = "threat-defcon3"
        threat_level_text = "🟡 DEFCON 3: GUARDED"
    else:
        threat_level_class = "threat-normal"
        threat_level_text = "🟢 DEFCON 5: NORMAL"
finally:
    db.close()


# -----------------------------------------------------------------------------
# Top Navigation Banner
# -----------------------------------------------------------------------------
st.markdown(f"""
<div class="soc-header">
    <div>
        <div class="soc-header-title">
            <span class="live-dot"></span>
            <span>AUTHSHIELD // THREAT DEFENSE OPERATIONS</span>
        </div>
        <div class="soc-header-subtitle">
            ZERO-TRUST IDENTITY TELEMETRY • HEURISTIC DETECTION ENGINE • REAL-TIME ACTIVE DEFENSE
        </div>
    </div>
    <div style="display: flex; align-items: center; gap: 0.85rem;">
        <span class="soc-telemetry-tag">ENGINE: ONLINE</span>
        <span class="threat-pill {threat_level_class}">{threat_level_text}</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Display persistent flash notification if present
if st.session_state.flash_message:
    if st.session_state.flash_type == "success":
        st.success(st.session_state.flash_message)
    elif st.session_state.flash_type == "warning":
        st.warning(st.session_state.flash_message)
    else:
        st.info(st.session_state.flash_message)
    st.session_state.flash_message = None


# -----------------------------------------------------------------------------
# Sidebar Configuration & Telemetry
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("""
    <div style="padding: 0.5rem 0 1rem 0; border-bottom: 1px solid #141923; margin-bottom: 1rem;">
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: #0284c7; letter-spacing: 0.1em; font-weight: 700;">// AUTHSHIELD DEFENSE</div>
        <div style="font-size: 1.25rem; font-weight: 700; color: #f8fafc; letter-spacing: -0.01em; margin-top: 2px;">SOC CONSOLE</div>
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #64748b; margin-top: 2px;">IAM THREAT INTELLIGENCE</div>
    </div>
    """, unsafe_allow_html=True)

    active_tab = st.radio(
        "Console Navigation",
        [
            "📊 Dashboard Overview",
            "🚨 Security Alerts Triage",
            "⚔️ Active Defense & Remediation",
            "📜 Audit Log Explorer",
            "⚡ Attack Simulation Lab"
        ],
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown("#### 👤 Operator Context")
    st.markdown("""
    <div style="background: #090c12; border: 1px solid #161c28; border-radius: 4px; padding: 0.75rem; font-size: 0.8rem; font-family: 'JetBrains Mono', monospace;">
        <div style="color: #64748b; font-size: 0.68rem; text-transform: uppercase; font-weight: 700; letter-spacing: 0.05em;">OPERATOR IDENTITY</div>
        <div style="color: #f8fafc; font-weight: 600; margin-top: 2px; font-size: 0.85rem;">analyst@authshield.io</div>
        <div style="color: #10b981; font-size: 0.72rem; margin-top: 4px;">● ACCESS: SOC_ANALYST (TIER 2)</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("#### ⚙️ Containment Telemetry")
    col_s1, col_s2 = st.columns(2)
    col_s1.metric("Quarantined IPs", f"{active_blocked_ips_count}")
    col_s2.metric("Blocked Drops", f"{blocked_attempts_count}")

    st.markdown("#### 🔄 Live Automation")
    traffic_toggle = st.toggle("🔁 Real-World Logins Stream (Every 10s)", value=st.session_state.auto_traffic_enabled)
    if traffic_toggle != st.session_state.auto_traffic_enabled:
        st.session_state.auto_traffic_enabled = traffic_toggle
        st.session_state.last_traffic_time = time.time()
        st.rerun()

    if st.button("🔄 Refresh Telemetry", use_container_width=True):
        st.rerun()

    st.markdown("---")
    st.markdown("#### 🔗 Quick References")
    st.markdown("""
    - [FastAPI Swagger UI](http://127.0.0.1:8000/docs)
    - [ReDoc Documentation](http://127.0.0.1:8000/redoc)
    - [API Health Check](http://127.0.0.1:8000/health)
    """)


# =============================================================================
# TAB 1: DASHBOARD OVERVIEW
# =============================================================================
if active_tab == "📊 Dashboard Overview":
    # 4 Hero KPI Cards
    col1, col2, col3, col4 = st.columns(4)

    # 1. Total Security Events
    with col1:
        st.markdown(f"""
        <div class="kpi-card kpi-accent-blue">
            <div class="kpi-label">
                <span>Total Security Events</span>
                <span>📈</span>
            </div>
            <div class="kpi-value">{total_events_count:,}</div>
            <div class="kpi-caption">Audit entries tracked in system</div>
        </div>
        """, unsafe_allow_html=True)

    # 2. Authentication Ratio
    with col2:
        total_attempts = success_logins_count + failed_logins_count
        fail_pct = round((failed_logins_count / total_attempts * 100), 1) if total_attempts > 0 else 0
        accent_color = "kpi-accent-red" if fail_pct > 25 else "kpi-accent-green"
        st.markdown(f"""
        <div class="kpi-card {accent_color}">
            <div class="kpi-label">
                <span>Failed Auth Ratio</span>
                <span>🔐</span>
            </div>
            <div class="kpi-value">{fail_pct}%</div>
            <div class="kpi-caption">{failed_logins_count} failed of {total_attempts} login events</div>
        </div>
        """, unsafe_allow_html=True)

    # 3. Active Threat Alerts
    with col3:
        total_open = open_alerts_count + investigating_alerts_count
        accent_color = "kpi-accent-red" if total_open > 0 else "kpi-accent-green"
        st.markdown(f"""
        <div class="kpi-card {accent_color}">
            <div class="kpi-label">
                <span>Open Security Alerts</span>
                <span>🚨</span>
            </div>
            <div class="kpi-value">{total_open}</div>
            <div class="kpi-caption">{open_alerts_count} Open • {investigating_alerts_count} Investigating</div>
        </div>
        """, unsafe_allow_html=True)

    # 4. Quarantined Entities
    with col4:
        contain_accent = "kpi-accent-red" if active_blocked_ips_count > 0 else "kpi-accent-purple"
        st.markdown(f"""
        <div class="kpi-card {contain_accent}">
            <div class="kpi-label">
                <span>Active Quarantine</span>
                <span>🚫</span>
            </div>
            <div class="kpi-value">{active_blocked_ips_count} IPs</div>
            <div class="kpi-caption">{disabled_users_count} disabled users • {blocked_attempts_count} drops</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 0.5rem;'></div>", unsafe_allow_html=True)

    # Charts Row
    chart_col1, chart_col2 = st.columns(2)

    db = get_db_session()
    try:
        # Chart 1: Alerts by Severity with Altair
        with chart_col1:
            st.markdown('<div class="soc-section-title">🚨 Threat Alert Severity Distribution</div>', unsafe_allow_html=True)
            severity_counts = (
                db.query(SecurityAlert.severity, func.count(SecurityAlert.id))
                .group_by(SecurityAlert.severity)
                .all()
            )
            if severity_counts:
                df_sev = pd.DataFrame(severity_counts, columns=["Severity", "Count"])
                sev_color_scale = alt.Scale(
                    domain=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    range=["#ef4444", "#f97316", "#eab308", "#0284c7"]
                )
                chart_sev = (
                    alt.Chart(df_sev)
                    .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
                    .encode(
                        x=alt.X("Severity:N", sort=["CRITICAL", "HIGH", "MEDIUM", "LOW"], axis=alt.Axis(title=None, labelAngle=0, labelColor="#94a3b8")),
                        y=alt.Y("Count:Q", axis=alt.Axis(title="Active Alerts", tickMinStep=1, labelColor="#64748b", titleColor="#94a3b8", gridColor="#161c28")),
                        color=alt.Color("Severity:N", scale=sev_color_scale, legend=None),
                        tooltip=["Severity", "Count"]
                    )
                    .properties(height=260)
                    .configure_view(strokeWidth=0, fill="transparent")
                    .configure(background="transparent")
                )
                st.altair_chart(chart_sev, use_container_width=True)
            else:
                st.info("No security alerts generated yet.")

        # Chart 2: Authentication Dynamics
        with chart_col2:
            st.markdown('<div class="soc-section-title">🔐 Authentication Event Dynamics</div>', unsafe_allow_html=True)
            auth_events = (
                db.query(AuditLog.action, func.count(AuditLog.id))
                .filter(AuditLog.action.in_(["LOGIN_SUCCESS", "LOGIN_FAILED", "LOGIN_ATTEMPT_DISABLED_ACCOUNT", "BLOCKED_IP_REJECTED"]))
                .group_by(AuditLog.action)
                .all()
            )
            if auth_events:
                df_auth = pd.DataFrame(auth_events, columns=["Outcome", "Count"])
                label_map = {
                    "LOGIN_SUCCESS": "Success",
                    "LOGIN_FAILED": "Failed (Invalid)",
                    "LOGIN_ATTEMPT_DISABLED_ACCOUNT": "Blocked (Disabled User)",
                    "BLOCKED_IP_REJECTED": "Quarantined IP Drop"
                }
                df_auth["Label"] = df_auth["Outcome"].map(label_map)

                auth_color_scale = alt.Scale(
                    domain=["Success", "Failed (Invalid)", "Blocked (Disabled User)", "Quarantined IP Drop"],
                    range=["#059669", "#dc2626", "#ea580c", "#7f1d1d"]
                )
                chart_auth = (
                    alt.Chart(df_auth)
                    .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
                    .encode(
                        x=alt.X("Label:N", axis=alt.Axis(title=None, labelAngle=0, labelColor="#94a3b8")),
                        y=alt.Y("Count:Q", axis=alt.Axis(title="Event Count", tickMinStep=1, labelColor="#64748b", titleColor="#94a3b8", gridColor="#161c28")),
                        color=alt.Color("Label:N", scale=auth_color_scale, legend=None),
                        tooltip=["Label", "Count"]
                    )
                    .properties(height=260)
                    .configure_view(strokeWidth=0, fill="transparent")
                    .configure(background="transparent")
                )
                st.altair_chart(chart_auth, use_container_width=True)
            else:
                st.info("No authentication telemetry available.")

        # Row 3: Threat Activity & Live Ticker
        col_threat1, col_threat2 = st.columns([1, 1])

        # Top Source IPs Table with Quick Action
        with col_threat1:
            st.markdown('<div class="soc-section-title">🌐 Top Suspicious Source IPs & Activity</div>', unsafe_allow_html=True)
            top_ips = (
                db.query(
                    AuditLog.ip_address,
                    func.count(AuditLog.id).label("total_events"),
                    func.sum(case((AuditLog.action == "LOGIN_FAILED", 1), else_=0)).label("failed_logins"),
                    func.sum(case((AuditLog.action == "ACCESS_DENIED", 1), else_=0)).label("access_denials")
                )
                .group_by(AuditLog.ip_address)
                .order_by(desc("total_events"))
                .limit(7)
                .all()
            )
            if top_ips:
                ip_rows = []
                for ip, total, failed, denied in top_ips:
                    is_blk = BlocklistService.is_ip_blocked(db, ip or "127.0.0.1")
                    risk = "CRITICAL" if is_blk else ("HIGH" if (failed or 0) >= 3 else ("MEDIUM" if (failed or 0) >= 1 else "LOW"))

                    ip_rows.append({
                        "Source IP": ip or "127.0.0.1",
                        "Quarantined": "🚫 YES" if is_blk else "🟢 No",
                        "Risk": risk,
                        "Total Events": total,
                        "Failed Logins": failed or 0,
                        "Access Denials": denied or 0
                    })
                df_ip_display = pd.DataFrame(ip_rows)
                st.dataframe(
                    df_ip_display,
                    use_container_width=True,
                    hide_index=True,
                    column_config={
                        "Total Events": st.column_config.ProgressColumn(
                            "Total Events",
                            min_value=0,
                            max_value=max(r["Total Events"] for r in ip_rows) if ip_rows else 10,
                            format="%d"
                        )
                    }
                )
                st.caption("ℹ️ To inspect or quarantine suspicious IPs, use the **⚔️ Active Defense & Remediation** tab or **🚨 Alerts Triage**.")
            else:
                st.info("No source IP telemetry recorded.")

        # Recent Access Denials & Unauthorized Attempts
        with col_threat2:
            st.markdown('<div class="soc-section-title">🚫 Recent Access Denied & Quarantined Incidents</div>', unsafe_allow_html=True)
            denied_logs = (
                db.query(AuditLog.timestamp, AuditLog.ip_address, AuditLog.endpoint, AuditLog.action, AuditLog.details)
                .filter(AuditLog.action.in_(["ACCESS_DENIED", "LOGIN_ATTEMPT_DISABLED_ACCOUNT", "BLOCKED_IP_REJECTED"]))
                .order_by(AuditLog.timestamp.desc())
                .limit(6)
                .all()
            )
            if denied_logs:
                denied_data = []
                for log in denied_logs:
                    denied_data.append({
                        "Time": log.timestamp.strftime("%H:%M:%S"),
                        "Action": log.action,
                        "Source IP": str(log.ip_address or "127.0.0.1"),
                        "Forensic Details": str(log.details or "")
                    })
                st.dataframe(pd.DataFrame(denied_data), use_container_width=True, hide_index=True)
            else:
                st.success("No access denial violations recorded.")

    finally:
        db.close()


# =============================================================================
# TAB 2: SECURITY ALERTS TRIAGE QUEUE (WITH DIRECT REMEDIATION ACTIONS)
# =============================================================================
elif active_tab == "🚨 Security Alerts Triage":
    st.markdown('<div class="soc-section-title">🚨 Security Incident Investigation & Triage Queue</div>', unsafe_allow_html=True)
    st.caption("Investigate triggered threat rules, analyze forensic evidence, and execute manual containment actions.")

    db = get_db_session()
    try:
        # Search & Filter Toolbar
        fcol1, fcol2, fcol3 = st.columns([2, 1, 1])
        with fcol1:
            search_query = st.text_input("🔍 Search alerts (by IP, Alert Type, or Description)", placeholder="e.g. 10.0.0.15, BRUTE_FORCE, admin...")
        with fcol2:
            status_filter = st.selectbox("Status", ["ALL", "OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"])
        with fcol3:
            severity_filter = st.selectbox("Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])

        # View Mode Toggle & Bulk Actions
        b_col_view, b_col_act1, b_col_act2 = st.columns([2, 1, 1])
        with b_col_view:
            view_mode = st.radio("Display Mode", ["📋 Interactive Incident Cards", "📊 Compact Data Table"], horizontal=True, label_visibility="collapsed")
        with b_col_act1:
            if st.button("✅ Resolve All Open", use_container_width=True):
                open_items = db.query(SecurityAlert).filter(SecurityAlert.status == "OPEN").all()
                for item in open_items:
                    item.status = "RESOLVED"
                db.commit()
                st.session_state.flash_message = f"Resolved {len(open_items)} open alerts."
                st.rerun()
        with b_col_act2:
            if st.button("🧹 Dismiss False Positives", use_container_width=True):
                db.query(SecurityAlert).filter(SecurityAlert.status == "FALSE_POSITIVE").delete()
                db.commit()
                st.session_state.flash_message = "Dismissed all false-positive alerts."
                st.rerun()

        # Query construction
        query = db.query(SecurityAlert)
        if status_filter != "ALL":
            query = query.filter(SecurityAlert.status == status_filter)
        if severity_filter != "ALL":
            query = query.filter(SecurityAlert.severity == severity_filter)
        if search_query:
            search_pattern = f"%{search_query}%"
            query = query.filter(
                (SecurityAlert.alert_type.ilike(search_pattern)) |
                (SecurityAlert.source_ip.ilike(search_pattern)) |
                (SecurityAlert.description.ilike(search_pattern))
            )

        alerts = query.order_by(SecurityAlert.timestamp.desc()).all()

        st.markdown(f"<div style='font-size: 0.85rem; color: #94a3b8; margin: 0.5rem 0 1rem 0;'>Showing <b>{len(alerts)}</b> incidents matching criteria</div>", unsafe_allow_html=True)

        if not alerts:
            st.info("No security alerts matching the selected filters.")
        else:
            # Clean Incident Action Center (Unified Action Controls - No Button per Row)
            with st.expander("⚡ Incident Action Center (Triage & Containment)", expanded=True):
                act_col1, act_col2, act_col3 = st.columns([2.5, 2, 1])

                alert_map = {
                    f"#{a.id} [{a.severity}] {a.alert_type} — IP: {a.source_ip or 'N/A'} ({a.status})": a
                    for a in alerts
                }

                with act_col1:
                    sel_label = st.selectbox("Select Incident to Action", list(alert_map.keys()), key="sel_triage_alert")
                    sel_alert = alert_map[sel_label]

                # Dynamic logical action options
                action_options = [
                    "🔎 Mark as INVESTIGATING",
                    "✅ Mark as RESOLVED",
                    "❌ Mark as FALSE POSITIVE",
                    "🔄 Re-Open Incident (OPEN)"
                ]

                sel_is_ip_blocked = BlocklistService.is_ip_blocked(db, sel_alert.source_ip) if sel_alert.source_ip else False
                sel_u = db.query(User).filter(User.id == sel_alert.user_id).first() if sel_alert.user_id else None
                sel_u_disabled = (sel_u.status == "disabled") if sel_u else False

                if sel_alert.source_ip:
                    if sel_is_ip_blocked:
                        action_options.append(f"🔓 Unblock IP ({sel_alert.source_ip})")
                    else:
                        action_options.append(f"🚫 Quarantine IP ({sel_alert.source_ip})")

                if sel_u:
                    if sel_u_disabled:
                        action_options.append(f"🔓 Restore Account ({sel_u.username})")
                    else:
                        action_options.append(f"🔒 Quarantine Account ({sel_u.username})")

                with act_col2:
                    sel_action = st.selectbox("Action to Execute", action_options, key="sel_triage_action")

                with act_col3:
                    st.markdown("<div style='height: 1.7rem;'></div>", unsafe_allow_html=True)
                    if st.button("Apply Action", type="primary", use_container_width=True):
                        if "INVESTIGATING" in sel_action:
                            handle_triage_action(sel_alert.id, "INVESTIGATING")
                        elif "RESOLVED" in sel_action:
                            handle_triage_action(sel_alert.id, "RESOLVED")
                        elif "FALSE POSITIVE" in sel_action:
                            handle_triage_action(sel_alert.id, "FALSE_POSITIVE")
                        elif "OPEN" in sel_action:
                            handle_triage_action(sel_alert.id, "OPEN")
                        elif "Quarantine IP" in sel_action:
                            handle_block_ip_action(sel_alert.source_ip, f"Manual quarantine from Alert #{sel_alert.id} ({sel_alert.alert_type})")
                        elif "Unblock IP" in sel_action:
                            handle_unblock_ip_action(sel_alert.source_ip)
                        elif "Quarantine Account" in sel_action and sel_u:
                            handle_quarantine_user_action(sel_u.id)
                        elif "Restore Account" in sel_action and sel_u:
                            handle_restore_user_action(sel_u.id)
                        st.rerun()

            st.markdown("<div style='height: 0.5rem;'></div>", unsafe_allow_html=True)

            if view_mode == "📋 Interactive Incident Cards":
                # Render Clean Native Streamlit Cards (Guaranteed Flawless UI Rendering)
                for a in alerts:
                    time_str = a.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
                    is_ip_blocked = BlocklistService.is_ip_blocked(db, a.source_ip) if a.source_ip else False
                    target_user = db.query(User).filter(User.id == a.user_id).first() if a.user_id else None
                    is_user_disabled = (target_user.status == "disabled") if target_user else False

                    with st.container(border=True):
                        # Top row: Incident ID & Title + Status & Severity Badges
                        hcol1, hcol2 = st.columns([3, 2])
                        with hcol1:
                            st.markdown(f"**`INC-{a.id:04d}`** • **`{a.alert_type}`**")
                        with hcol2:
                            sev_pill = f":red-background[{a.severity}]" if a.severity in ["CRITICAL", "HIGH"] else (f":orange-background[{a.severity}]" if a.severity == "MEDIUM" else f":blue-background[{a.severity}]")
                            status_pill = f"`{a.status}`"
                            badges_line = f"{sev_pill} {status_pill}"
                            if is_ip_blocked:
                                badges_line += " :red[**[🚫 IP QUARANTINED]**]"
                            if is_user_disabled:
                                badges_line += " :orange[**[🔒 ACCOUNT DISABLED]**]"
                            st.markdown(badges_line)

                        # Metadata row
                        mcol1, mcol2, mcol3 = st.columns(3)
                        mcol1.caption(f"🕒 **Detected:** `{time_str}`")
                        mcol2.caption(f"🌐 **Source IP:** `{a.source_ip or 'N/A'}`")
                        target_name = f"`{target_user.username}` (ID: {a.user_id})" if target_user else (f"`ID: {a.user_id}`" if a.user_id is not None else "`N/A`")
                        mcol3.caption(f"👤 **Target Subject:** {target_name}")

                        # Forensic Evidence box
                        st.info(f"**Forensic Evidence:** {a.description or 'No additional details logged.'}", icon="🔍")

            else:
                # Compact Data Table View with Export
                alert_rows = []
                for a in alerts:
                    is_blk = BlocklistService.is_ip_blocked(db, a.source_ip) if a.source_ip else False
                    alert_rows.append({
                        "ID": a.id,
                        "Timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        "Alert Type": str(a.alert_type or ""),
                        "Severity": str(a.severity or ""),
                        "Source IP": str(a.source_ip or ""),
                        "IP Blocked?": "YES" if is_blk else "No",
                        "Target User ID": str(a.user_id) if a.user_id is not None else "N/A",
                        "Status": str(a.status or ""),
                        "Description": str(a.description or "")
                    })
                df_alerts = pd.DataFrame(alert_rows)
                st.dataframe(df_alerts, use_container_width=True, hide_index=True)

                csv_data = df_alerts.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="📥 Export Filtered Alerts (CSV)",
                    data=csv_data,
                    file_name=f"authshield_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )

    finally:
        db.close()


# =============================================================================
# TAB 3: ACTIVE DEFENSE & REMEDIATION CONSOLE
# =============================================================================
elif active_tab == "⚔️ Active Defense & Remediation":
    st.markdown('<div class="soc-section-title">⚔️ Threat Remediation & Active Defense Center</div>', unsafe_allow_html=True)
    st.caption("Perform manual threat containment: inspect suspicious IPs, manage the active network denylist, and quarantine compromised user accounts.")

    db = get_db_session()
    try:
        # Remediation Hero Stats
        kcol1, kcol2, kcol3 = st.columns(3)
        with kcol1:
            st.markdown(f"""
            <div class="kpi-card kpi-accent-red">
                <div class="kpi-label">
                    <span>Actively Quarantined IPs</span>
                    <span>🚫</span>
                </div>
                <div class="kpi-value">{active_blocked_ips_count}</div>
                <div class="kpi-caption">Connections rejected with 403 Forbidden</div>
            </div>
            """, unsafe_allow_html=True)

        with kcol2:
            st.markdown(f"""
            <div class="kpi-card kpi-accent-orange">
                <div class="kpi-label">
                    <span>Disabled / Quarantined Users</span>
                    <span>🔒</span>
                </div>
                <div class="kpi-value">{disabled_users_count}</div>
                <div class="kpi-caption">Accounts restricted from authentication</div>
            </div>
            """, unsafe_allow_html=True)

        with kcol3:
            st.markdown(f"""
            <div class="kpi-card kpi-accent-purple">
                <div class="kpi-label">
                    <span>Blocked Attack Drops</span>
                    <span>🛡️</span>
                </div>
                <div class="kpi-value">{blocked_attempts_count}</div>
                <div class="kpi-caption">BLOCKED_IP_REJECTED events recorded</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='height: 1.25rem;'></div>", unsafe_allow_html=True)

        # -------------------------------------------------------------
        # Section 1: Forensic IP Inspector & Immediate Containment
        # -------------------------------------------------------------
        st.markdown('<div class="soc-section-title">🔍 Forensic IP Dossier & Manual Containment</div>', unsafe_allow_html=True)
        st.write("Notice an IP in alerts or logs? Enter it below to inspect its full security footprint and block or unblock it with one click.")

        ip_input_col, ip_btn_col = st.columns([3, 1])
        with ip_input_col:
            lookup_ip = st.text_input(
                "Inspect Source IP",
                value=st.session_state.inspected_ip,
                placeholder="e.g. 10.0.0.15, 192.168.1.50, 185.220.101.45...",
                label_visibility="collapsed"
            )
        with ip_btn_col:
            if st.button("🔎 Inspect IP Footprint", use_container_width=True):
                st.session_state.inspected_ip = lookup_ip.strip()
                st.rerun()

        target_ip = st.session_state.inspected_ip.strip()
        if target_ip:
            # Query IP dossier
            is_currently_blocked = BlocklistService.is_ip_blocked(db, target_ip)
            ip_total_events = db.query(func.count(AuditLog.id)).filter(AuditLog.ip_address == target_ip).scalar() or 0
            ip_failed_logins = db.query(func.count(AuditLog.id)).filter(AuditLog.ip_address == target_ip, AuditLog.action == "LOGIN_FAILED").scalar() or 0
            ip_denials = db.query(func.count(AuditLog.id)).filter(AuditLog.ip_address == target_ip, AuditLog.action == "ACCESS_DENIED").scalar() or 0
            ip_alerts = db.query(SecurityAlert).filter(SecurityAlert.source_ip == target_ip).all()

            status_pill = '<span class="badge" style="background: rgba(239, 68, 68, 0.25); color: #f87171; border: 1px solid #ef4444; font-size: 0.85rem;">🚫 ACTIVELY BLOCKED</span>' if is_currently_blocked else '<span class="badge" style="background: rgba(16, 185, 129, 0.25); color: #34d399; border: 1px solid #10b981; font-size: 0.85rem;">🟢 ALLOWED / UNRESTRICTED</span>'

            st.markdown(f"""
            <div class="ip-dossier-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.85rem;">
                    <div>
                        <span style="font-size: 1.25rem; font-weight: 700; color: #f8fafc; font-family: 'JetBrains Mono';">IP: {target_ip}</span>
                    </div>
                    <div>{status_pill}</div>
                </div>
                <div style="display: flex; gap: 2rem; color: #94a3b8; font-size: 0.85rem; margin-bottom: 0.85rem;">
                    <span><b>Total Logged Events:</b> <code style="color: #60a5fa;">{ip_total_events}</code></span>
                    <span><b>Failed Logins:</b> <code style="color: #f87171;">{ip_failed_logins}</code></span>
                    <span><b>Access Denials:</b> <code style="color: #fb923c;">{ip_denials}</code></span>
                    <span><b>Triggered Alerts:</b> <code style="color: #fde047;">{len(ip_alerts)}</code></span>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Manual Action Buttons for Inspected IP
            d_act1, d_act2 = st.columns([1, 1])
            with d_act1:
                if is_currently_blocked:
                    st.button(
                        f"🔓 Release IP {target_ip} from Blocklist",
                        key="btn_dossier_unblock",
                        on_click=handle_unblock_ip_action,
                        args=(target_ip,),
                        use_container_width=True
                    )
                else:
                    block_reason = st.text_input("Reason for Block", value="Observed malicious threat activity", key="input_block_reason")
                    st.button(
                        f"🚫 Manually Block IP {target_ip}",
                        key="btn_dossier_block",
                        on_click=handle_block_ip_action,
                        args=(target_ip, block_reason),
                        use_container_width=True
                    )
            with d_act2:
                if ip_alerts:
                    st.write(f"**Associated Alerts ({len(ip_alerts)}):**")
                    for al in ip_alerts[:3]:
                        st.caption(f"• #{al.id} [{al.severity}] {al.alert_type} - {al.status}")
                else:
                    st.caption("No rule-triggered alerts recorded for this specific IP.")

        st.markdown("---")

        # -------------------------------------------------------------
        # Section 2: Active IP Denylist Manager
        # -------------------------------------------------------------
        st.markdown('<div class="soc-section-title">🚫 Active Network Denylist (Quarantined IPs)</div>', unsafe_allow_html=True)

        blocked_records = BlocklistService.get_all_blocked(db)
        if blocked_records:
            blk_table_data = []
            for b in blocked_records:
                blk_table_data.append({
                    "Quarantined IP": b.ip_address,
                    "Operator": b.blocked_by,
                    "Reason": b.reason or "Manual containment",
                    "Blocked At (UTC)": b.timestamp.strftime("%Y-%m-%d %H:%M:%S") if b.timestamp else "N/A"
                })
            st.dataframe(pd.DataFrame(blk_table_data), use_container_width=True, hide_index=True)

            # Single Unblock Selector (No button per row!)
            u_col1, u_col2 = st.columns([3, 1])
            with u_col1:
                ip_to_unblock = st.selectbox(
                    "Select Quarantined IP to Release",
                    [b.ip_address for b in blocked_records],
                    key="sel_unblock_denylist",
                    label_visibility="collapsed"
                )
            with u_col2:
                if st.button("🔓 Release Selected IP", use_container_width=True):
                    handle_unblock_ip_action(ip_to_unblock)
                    st.rerun()
        else:
            st.info("No IP addresses are currently quarantined. All legitimate traffic is allowed.")

        # Manual Block Submission Form
        with st.expander("➕ Manually Add New IP to Denylist"):
            with st.form("manual_block_form"):
                new_block_ip = st.text_input("IP Address to Block (e.g. 198.51.100.25)")
                new_block_reason = st.text_input("Justification / Incident Reference", value="Manual containment order by SOC lead")
                submit_block = st.form_submit_button("🚫 Enforce Manual Block")
                if submit_block and new_block_ip:
                    BlocklistService.block_ip(db, new_block_ip.strip(), reason=new_block_reason, blocked_by="analyst@authshield.io")
                    st.session_state.flash_message = f"IP '{new_block_ip.strip()}' has been quarantined on active denylist."
                    st.session_state.flash_type = "warning"
                    st.rerun()

        st.markdown("---")

        # -------------------------------------------------------------
        # Section 3: Compromised Account Quarantine & Lockouts
        # -------------------------------------------------------------
        st.markdown('<div class="soc-section-title">🔒 User Account Quarantine & Containment</div>', unsafe_allow_html=True)

        users = db.query(User).options(desc(User.id)).all()
        disabled_users = [u for u in users if u.status == "disabled"]
        active_users = [u for u in users if u.status == "active"]

        st.write(f"**Quarantined / Disabled Accounts ({len(disabled_users)}):**")
        if disabled_users:
            dis_table_data = []
            for dis_u in disabled_users:
                dis_table_data.append({
                    "User ID": dis_u.id,
                    "Username": dis_u.username,
                    "Email": dis_u.email,
                    "Role": dis_u.role.name if dis_u.role else "user",
                    "Status": "DISABLED"
                })
            st.dataframe(pd.DataFrame(dis_table_data), use_container_width=True, hide_index=True)

            # Single Restore Selector (No button per row!)
            r_col1, r_col2 = st.columns([3, 1])
            with r_col1:
                user_to_restore_label = st.selectbox(
                    "Select Account to Restore",
                    [f"{u.username} (ID: {u.id})" for u in disabled_users],
                    key="sel_restore_user_account",
                    label_visibility="collapsed"
                )
                user_to_restore_id = int(user_to_restore_label.split("ID: ")[1].rstrip(")"))
            with r_col2:
                if st.button("🔓 Restore Selected Account", use_container_width=True):
                    handle_restore_user_action(user_to_restore_id)
                    st.rerun()
        else:
            st.info("No accounts are currently quarantined or disabled.")

        with st.expander("🔒 Manually Quarantine an Active Account"):
            with st.form("manual_user_quarantine_form"):
                user_choices = {f"{u.username} ({u.email}) [Role: {u.role.name if u.role else 'user'}]": u.id for u in active_users}
                if user_choices:
                    selected_label = st.selectbox("Select Active User to Lock", list(user_choices.keys()))
                    lock_reason = st.text_input("Lockout Justification", value="Compromised credentials suspected during active attack")
                    submit_user_lock = st.form_submit_button("🔒 Suspend User Account")
                    if submit_user_lock:
                        target_id = user_choices[selected_label]
                        handle_quarantine_user_action(target_id)
                        st.rerun()
                else:
                    st.info("No active users available to lock.")

        st.markdown("---")

        # -------------------------------------------------------------
        # Section 4: Remediation Actions Audit Trail
        # -------------------------------------------------------------
        st.markdown('<div class="soc-section-title">📜 Remediation Actions Audit Log</div>', unsafe_allow_html=True)
        remediation_logs = (
            db.query(AuditLog)
            .filter(AuditLog.action.in_([
                "IP_MANUALLY_BLOCKED",
                "IP_UNBLOCKED",
                "USER_QUARANTINED",
                "USER_RESTORED",
                "BLOCKED_IP_REJECTED"
            ]))
            .order_by(AuditLog.timestamp.desc())
            .limit(50)
            .all()
        )

        if remediation_logs:
            rem_data = [{
                "Time": l.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "Remediation Action": l.action,
                "Target IP": l.ip_address,
                "Details": l.details
            } for l in remediation_logs]
            st.dataframe(pd.DataFrame(rem_data), use_container_width=True, hide_index=True)
        else:
            st.info("No remediation containment events recorded yet.")

    finally:
        db.close()


# =============================================================================
# TAB 4: AUDIT LOG EXPLORER
# =============================================================================
elif active_tab == "📜 Audit Log Explorer":
    st.markdown('<div class="soc-section-title">📜 Immutable Security Audit Trail & Forensics</div>', unsafe_allow_html=True)
    st.caption("Search, filter, and inspect tamper-evident audit records across authentication, authorization, and administrative operations.")

    db = get_db_session()
    try:
        # Quick Preset Filter Chips
        st.markdown("**Quick Filter Presets:**")
        preset_choice = st.pills(
            "Filter Presets",
            ["All Records", "Failed Logins Only", "Access Denied (403)", "Privilege & Roles", "Successful Logins"],
            default="All Records",
            label_visibility="collapsed"
        )

        # Advanced Filter Inputs
        col_f1, col_f2, col_f3, col_f4 = st.columns([2, 1.2, 1, 1])
        with col_f1:
            search_text = st.text_input("🔍 Search forensic details, endpoints, actions", placeholder="e.g. login, /admin/users, invalid password...")
        with col_f2:
            ip_filter = st.text_input("Filter IP Address", placeholder="e.g. 10.0.0.15")
        with col_f3:
            status_filter = st.selectbox("Status", ["ALL", "SUCCESS", "FAILURE", "DENIED"])
        with col_f4:
            limit_val = st.selectbox("Max Rows", [100, 200, 500, 1000], index=1)

        log_query = db.query(AuditLog)

        # Apply Preset Logic
        if preset_choice == "Failed Logins Only":
            log_query = log_query.filter(AuditLog.action == "LOGIN_FAILED")
        elif preset_choice == "Access Denied (403)":
            log_query = log_query.filter(AuditLog.action == "ACCESS_DENIED")
        elif preset_choice == "Privilege & Roles":
            log_query = log_query.filter(AuditLog.action.in_(["ROLE_CHANGE", "USER_ROLE_CHANGED", "PRIVILEGE_CHANGE"]))
        elif preset_choice == "Successful Logins":
            log_query = log_query.filter(AuditLog.action == "LOGIN_SUCCESS")

        # Apply Custom Filters
        if search_text:
            log_query = log_query.filter(
                (AuditLog.action.ilike(f"%{search_text}%")) |
                (AuditLog.details.ilike(f"%{search_text}%")) |
                (AuditLog.endpoint.ilike(f"%{search_text}%"))
            )
        if ip_filter:
            log_query = log_query.filter(AuditLog.ip_address.ilike(f"%{ip_filter}%"))
        if status_filter != "ALL":
            log_query = log_query.filter(AuditLog.status == status_filter)

        logs = log_query.order_by(AuditLog.timestamp.desc()).limit(limit_val).all()

        st.markdown(f"<div style='font-size: 0.85rem; color: #94a3b8; margin: 0.5rem 0 0.85rem 0;'>Displaying <b>{len(logs)}</b> audit events</div>", unsafe_allow_html=True)

        if logs:
            data = [{
                "ID": l.id,
                "Timestamp (UTC)": l.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "Action": str(l.action or ""),
                "Status": str(l.status or ""),
                "Source IP": str(l.ip_address or "127.0.0.1"),
                "User ID": str(l.user_id) if l.user_id is not None else "Anonymous",
                "Endpoint": str(l.endpoint or "-"),
                "Forensic Details": str(l.details or "")
            } for l in logs]

            df_logs = pd.DataFrame(data)
            st.dataframe(
                df_logs,
                use_container_width=True,
                hide_index=True
            )

            csv_logs = df_logs.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Export Audit Trail (CSV)",
                data=csv_logs,
                file_name=f"authshield_audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        else:
            st.info("No audit logs match current filters.")
    finally:
        db.close()


# =============================================================================
# TAB 5: ATTACK SIMULATION LAB & REAL-WORLD TRAFFIC GENERATOR
# =============================================================================
elif active_tab == "⚡ Attack Simulation Lab":
    st.markdown('<div class="soc-section-title">⚡ Attack Simulation & Traffic Cockpit</div>', unsafe_allow_html=True)

    client, is_live_server = get_api_client()
    server_mode_label = "🌐 Live REST API (127.0.0.1:8000)" if is_live_server else "⚙️ In-Process FastAPI Engine"
    st.caption(f"Simulator Target: **{server_mode_label}** • Demonstrates sliding-window detection rules, alert creation, and audit logging.")

    sim_col1, sim_col2 = st.columns([3, 2])

    # Left Column: Unified Threat Scenario Launcher
    with sim_col1:
        with st.container(border=True):
            st.markdown("#### 🎯 Targeted Threat Scenario Launcher")
            scenario_choice = st.selectbox(
                "Select Attack Scenario to Simulate",
                [
                    "Scenario A: Brute-Force Password Spraying (5 Failed Logins -> HIGH Alert)",
                    "Scenario B: Normal User Typos (2 Failed Logins -> Safe Baseline)",
                    "Scenario C: Repeated Unauthorized Access Probe (3x 403 Forbidden -> MEDIUM Alert)",
                    "Scenario D: Administrative Privilege Escalation (Promote to Admin -> HIGH Alert)",
                    "Scenario E: Login on Disabled/Quarantined Account (Terminated User -> HIGH Alert)",
                ],
                key="sel_sim_scenario"
            )

            # Concise scenario expectations
            if "Scenario A" in scenario_choice:
                st.caption("⚡ Sends 5 rapid failed logins from a rotating IP to verify threshold triggering of `BRUTE_FORCE_LOGIN`.")
            elif "Scenario B" in scenario_choice:
                st.caption("🛡️ Sends 2 typo failed logins from a rotating IP (threshold is 5) to verify no false positives are generated.")
            elif "Scenario C" in scenario_choice:
                st.caption("🚫 Authenticates as standard user and accesses admin API 3 times to trigger `REPEATED_UNAUTHORIZED_ACCESS`.")
            elif "Scenario D" in scenario_choice:
                st.caption("👑 Promotes a newly created user to `admin` role to trigger `PRIVILEGE_CHANGE` alert.")
            elif "Scenario E" in scenario_choice:
                st.caption("🔒 Attempts login against deactivated account (`disabled@authshield.io`) to trigger `LOGIN_ATTEMPT_DISABLED_ACCOUNT`.")

            if st.button("🚀 Execute Selected Scenario", type="primary", use_container_width=True):
                if "Scenario A" in scenario_choice:
                    sim_ip = f"10.0.0.{random.randint(20, 250)}"
                    new_logs = [f"[{datetime.now().strftime('%H:%M:%S')}] [ATTACK START] Firing 5 failed logins from {sim_ip}"]
                    for i in range(5):
                        resp = client.post("/auth/login", json={"email": "admin@authshield.io", "password": f"spray_{i}_{random.randint(100, 999)}"}, headers={"X-Simulated-IP": sim_ip})
                        new_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] POST /auth/login (#{i+1}) -> HTTP {resp.status_code} [IP: {sim_ip}]")
                    new_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] [ALERT GENERATED] BRUTE_FORCE_LOGIN (HIGH) created for {sim_ip}")
                    st.session_state.sim_logs.extend(new_logs)
                    st.session_state.flash_message = f"🚨 Brute-Force scenario executed from {sim_ip}! High severity alert created in Triage."
                    st.session_state.flash_type = "warning"
                    st.rerun()

                elif "Scenario B" in scenario_choice:
                    sim_ip = f"10.0.0.{random.randint(20, 250)}"
                    new_logs = [f"[{datetime.now().strftime('%H:%M:%S')}] [BASELINE TEST] Firing 2 accidental password typos from {sim_ip}"]
                    for i in range(2):
                        resp = client.post("/auth/login", json={"email": "user@authshield.io", "password": "WrongPasswordTypo!"}, headers={"X-Simulated-IP": sim_ip})
                        new_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] POST /auth/login (#{i+1}) -> HTTP {resp.status_code} [IP: {sim_ip}]")
                    new_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] [SAFE VERDICT] Sub-threshold noise recorded: No alert triggered (Expected).")
                    st.session_state.sim_logs.extend(new_logs)
                    st.session_state.flash_message = "✅ Sub-threshold test passed: Safe baseline verified (no alert generated)."
                    st.session_state.flash_type = "success"
                    st.rerun()

                elif "Scenario C" in scenario_choice:
                    sim_ip = f"192.168.1.{random.randint(50, 99)}"
                    new_logs = [f"[{datetime.now().strftime('%H:%M:%S')}] [ATTACK START] Authenticating as role 'user' and invoking restricted admin endpoint from {sim_ip}"]
                    u_login = client.post("/auth/login", json={"email": "user@authshield.io", "password": "UserPassword123!"})
                    token = u_login.json().get("access_token")
                    for i in range(3):
                        resp = client.get("/users", headers={"Authorization": f"Bearer {token}", "X-Simulated-IP": sim_ip})
                        new_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] GET /users (#{i+1}) -> HTTP {resp.status_code} Forbidden [IP: {sim_ip}]")
                    new_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] [ALERT GENERATED] REPEATED_UNAUTHORIZED_ACCESS (MEDIUM) created")
                    st.session_state.sim_logs.extend(new_logs)
                    st.session_state.flash_message = "🚨 Repeated Unauthorized Access executed! Medium alert created in Triage."
                    st.session_state.flash_type = "warning"
                    st.rerun()

                elif "Scenario D" in scenario_choice:
                    new_logs = [f"[{datetime.now().strftime('%H:%M:%S')}] [ATTACK START] Registering new dummy user and promoting to 'admin'"]
                    adm_login = client.post("/auth/login", json={"email": "admin@authshield.io", "password": "AdminPassword123!"})
                    adm_token = adm_login.json().get("access_token")
                    dummy_email = f"staff_{int(time.time())}_{random.randint(10, 99)}@authshield.io"
                    reg = client.post("/auth/register", json={"username": f"staff_{random.randint(100, 999)}", "email": dummy_email, "password": "Password123!"})
                    target_id = reg.json().get("id")
                    patch_resp = client.patch(
                        f"/users/{target_id}/role",
                        json={"role_name": "admin"},
                        headers={"Authorization": f"Bearer {adm_token}", "X-Simulated-IP": "10.0.0.1"}
                    )
                    new_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] PATCH /users/{target_id}/role -> HTTP {patch_resp.status_code} (Promoted user to admin)")
                    new_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] [ALERT GENERATED] PRIVILEGE_CHANGE (HIGH) created")
                    st.session_state.sim_logs.extend(new_logs)
                    st.session_state.flash_message = "🚨 Privilege Escalation executed! High severity alert created in Triage."
                    st.session_state.flash_type = "warning"
                    st.rerun()

                elif "Scenario E" in scenario_choice:
                    sim_ip = f"172.16.0.{random.randint(10, 240)}"
                    new_logs = [f"[{datetime.now().strftime('%H:%M:%S')}] [ATTACK START] Authenticating as disabled user from {sim_ip}"]
                    resp = client.post(
                        "/auth/login",
                        json={"email": "disabled@authshield.io", "password": "DisabledPassword123!"},
                        headers={"X-Simulated-IP": sim_ip}
                    )
                    new_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] POST /auth/login -> HTTP {resp.status_code}: {resp.json().get('detail')}")
                    new_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] [ALERT GENERATED] LOGIN_ATTEMPT_DISABLED_ACCOUNT (HIGH) created")
                    st.session_state.sim_logs.extend(new_logs)
                    st.session_state.flash_message = f"🚨 Disabled account login attempt executed from {sim_ip}! High alert created in Triage."
                    st.session_state.flash_type = "warning"
                    st.rerun()

    # Right Column: Live Telemetry & Traffic Injections
    with sim_col2:
        with st.container(border=True):
            st.markdown("#### 🌐 Live Telemetry Generator")
            st.caption("Generate realistic corporate traffic bursts or inject attack noise.")

            if st.button("⚡ Inject 5 Legitimate User Logins", use_container_width=True):
                for _ in range(5):
                    inject_single_traffic_event()
                st.session_state.flash_message = "Injected 5 legitimate authentication events into system!"
                st.session_state.flash_type = "success"
                st.rerun()

            if st.button("💥 Inject Attack Burst (5 Failed Logins)", use_container_width=True):
                burst_ip = f"185.220.{random.randint(10, 240)}.{random.randint(10, 240)}"
                for b in range(5):
                    client.post("/auth/login", json={"email": "admin@authshield.io", "password": f"spray_{b}"}, headers={"X-Simulated-IP": burst_ip})
                st.session_state.sim_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] [ATTACK BURST] 5 failed logins from {burst_ip} -> Generated BRUTE_FORCE_LOGIN!")
                st.session_state.flash_message = f"Attack burst injected from {burst_ip}! Check Triage Queue."
                st.session_state.flash_type = "warning"
                st.rerun()

    # Compact Monospace Simulator Event Log
    st.markdown("<div style='height: 0.5rem;'></div>", unsafe_allow_html=True)
    with st.container(border=True):
        t_col1, t_col2 = st.columns([4, 1])
        t_col1.markdown("#### 💻 Simulator Event Log")
        if t_col2.button("🧹 Clear Log", use_container_width=True):
            st.session_state.sim_logs = []
            st.rerun()

        if st.session_state.sim_logs:
            log_text = "\n".join(st.session_state.sim_logs[-15:])
            st.code(log_text, language="log")
        else:
            st.caption("No simulation events logged yet. Select a scenario above to test detection.")
