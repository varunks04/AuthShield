"""AuthShield Security Operations Center (SOC) & Monitoring Dashboard."""

import streamlit as st
import pandas as pd
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database.connection import SessionLocal
from app.models.user import User
from app.models.role import Role
from app.models.audit import AuditLog
from app.models.alert import SecurityAlert
from app.services.audit_service import AuditService
from app.services.alert_service import AlertService
from app.detection.engine import DetectionEngine

st.set_page_config(
    page_title="AuthShield — Security Operations & IAM Monitoring",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1e293b;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1rem;
        color: #64748b;
        margin-bottom: 1.5rem;
    }
    .metric-box {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 1rem;
        text-align: center;
    }
    .badge-critical { background-color: #fee2e2; color: #b91c1c; padding: 2px 8px; border-radius: 4px; font-weight: 600; }
    .badge-high { background-color: #ffedd5; color: #c2410c; padding: 2px 8px; border-radius: 4px; font-weight: 600; }
    .badge-medium { background-color: #fef9c3; color: #a16207; padding: 2px 8px; border-radius: 4px; font-weight: 600; }
    .badge-low { background-color: #f1f5f9; color: #475569; padding: 2px 8px; border-radius: 4px; font-weight: 600; }
</style>
""", unsafe_allow_html=True)


def get_db_session() -> Session:
    return SessionLocal()


# Top Navigation / Title
st.markdown("<div class='main-header'>🛡️ AuthShield Security Monitoring Center</div>", unsafe_allow_html=True)
st.markdown(
    "<div class='sub-header'>Real-time Identity Access Management (IAM), Rule-based Threat Detection & Security Audit Logging</div>",
    unsafe_allow_html=True
)

# Sidebar
st.sidebar.image("https://img.icons8.com/color/96/shield.png", width=64)
st.sidebar.title("Navigation")
active_tab = st.sidebar.radio(
    "Select Console View",
    ["📊 Dashboard Overview", "🚨 Security Alerts Triage", "📜 Audit Log Explorer", "⚡ Attack Simulation Lab"]
)

st.sidebar.markdown("---")
st.sidebar.markdown("### ⚙️ System Status")
st.sidebar.success("Detection Engine: ACTIVE")
st.sidebar.info("Database: Connected")
if st.sidebar.button("🔄 Refresh Data"):
    st.rerun()

# -------------------------------------------------------------
# TAB 1: OVERVIEW & METRICS
# -------------------------------------------------------------
if active_tab == "📊 Dashboard Overview":
    db = get_db_session()
    try:
        total_users = db.query(func.count(User.id)).scalar() or 0
        disabled_users = db.query(func.count(User.id)).filter(User.status == "disabled").scalar() or 0
        total_events = db.query(func.count(AuditLog.id)).scalar() or 0
        failed_logins = db.query(func.count(AuditLog.id)).filter(AuditLog.action == "LOGIN_FAILED").scalar() or 0
        open_alerts = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.status == "OPEN").scalar() or 0
        high_critical_alerts = (
            db.query(func.count(SecurityAlert.id))
            .filter(SecurityAlert.severity.in_(["HIGH", "CRITICAL"]))
            .scalar() or 0
        )

        col1, col2, col3, col4, col5, col6 = st.columns(6)
        col1.metric("Total Users", total_users)
        col2.metric("Disabled Accounts", disabled_users)
        col3.metric("Security Events", total_events)
        col4.metric("Failed Logins", failed_logins)
        col5.metric("Open Alerts", open_alerts)
        col6.metric("High/Crit Alerts", high_critical_alerts)

        st.markdown("---")

        # Visualizations
        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            st.subheader("🚨 Alerts by Severity")
            alerts = db.query(SecurityAlert.severity, func.count(SecurityAlert.id)).group_by(SecurityAlert.severity).all()
            if alerts:
                df_sev = pd.DataFrame(alerts, columns=["Severity", "Count"])
                st.bar_chart(df_sev.set_index("Severity"))
            else:
                st.info("No security alerts recorded yet.")

        with chart_col2:
            st.subheader("🔐 Authentication Outcomes")
            auth_events = (
                db.query(AuditLog.action, func.count(AuditLog.id))
                .filter(AuditLog.action.in_(["LOGIN_SUCCESS", "LOGIN_FAILED", "LOGIN_ATTEMPT_DISABLED_ACCOUNT"]))
                .group_by(AuditLog.action)
                .all()
            )
            if auth_events:
                df_auth = pd.DataFrame(auth_events, columns=["Outcome", "Count"])
                st.bar_chart(df_auth.set_index("Outcome"))
            else:
                st.info("No authentication events recorded yet.")

        chart_col3, chart_col4 = st.columns(2)

        with chart_col3:
            st.subheader("🌐 Top Source IPs")
            top_ips = (
                db.query(AuditLog.ip_address, func.count(AuditLog.id))
                .group_by(AuditLog.ip_address)
                .order_by(func.count(AuditLog.id).desc())
                .limit(7)
                .all()
            )
            if top_ips:
                df_ips = pd.DataFrame(top_ips, columns=["IP Address", "Event Count"])
                st.dataframe(df_ips, use_container_width=True, hide_index=True)
            else:
                st.info("No IP activity logged yet.")

        with chart_col4:
            st.subheader("🚫 Recent Unauthorized Access Attempts")
            denied_logs = (
                db.query(AuditLog.timestamp, AuditLog.ip_address, AuditLog.details)
                .filter(AuditLog.action == "ACCESS_DENIED")
                .order_by(AuditLog.timestamp.desc())
                .limit(5)
                .all()
            )
            if denied_logs:
                df_denied = pd.DataFrame([
                    {"Time": log.timestamp.strftime("%H:%M:%S"), "IP": log.ip_address, "Details": log.details}
                    for log in denied_logs
                ])
                st.dataframe(df_denied, use_container_width=True, hide_index=True)
            else:
                st.info("No access denial events recorded.")

    finally:
        db.close()

# -------------------------------------------------------------
# TAB 2: SECURITY ALERTS TRIAGE
# -------------------------------------------------------------
elif active_tab == "🚨 Security Alerts Triage":
    st.subheader("Security Alert Investigation & Triage Queue")
    db = get_db_session()
    try:
        filter_col1, filter_col2 = st.columns(2)
        with filter_col1:
            status_filter = st.selectbox(
                "Filter by Status",
                ["ALL", "OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
            )
        with filter_col2:
            severity_filter = st.selectbox(
                "Filter by Severity",
                ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
            )

        query = db.query(SecurityAlert)
        if status_filter != "ALL":
            query = query.filter(SecurityAlert.status == status_filter)
        if severity_filter != "ALL":
            query = query.filter(SecurityAlert.severity == severity_filter)

        alerts = query.order_by(SecurityAlert.timestamp.desc()).all()

        if not alerts:
            st.info("No security alerts matching the selected filters.")
        else:
            alert_rows = []
            for a in alerts:
                alert_rows.append({
                    "ID": a.id,
                    "Time": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "Type": a.alert_type,
                    "Severity": a.severity,
                    "Source IP": a.source_ip,
                    "User ID": a.user_id or "N/A",
                    "Status": a.status,
                    "Description": a.description
                })
            df_alerts = pd.DataFrame(alert_rows)
            st.dataframe(df_alerts, use_container_width=True, hide_index=True)

            st.markdown("---")
            st.markdown("### 🛠️ Alert Triage Action")
            triage_col1, triage_col2, triage_col3 = st.columns([1, 1, 1])
            with triage_col1:
                selected_alert_id = st.selectbox("Select Alert ID to Triage", [a.id for a in alerts])
            with triage_col2:
                new_status = st.selectbox("New Triage Status", ["INVESTIGATING", "RESOLVED", "FALSE_POSITIVE", "OPEN"])
            with triage_col3:
                st.write("")
                st.write("")
                if st.button("Apply Status Change"):
                    AlertService.update_status(db, selected_alert_id, new_status)
                    AuditService.log_event(
                        db=db,
                        action="ALERT_STATUS_UPDATED",
                        endpoint="/dashboard/alerts",
                        status="SUCCESS",
                        ip_address="127.0.0.1",
                        details=f"Alert #{selected_alert_id} triage updated to '{new_status}' via SOC Dashboard"
                    )
                    st.success(f"Alert #{selected_alert_id} transitioned to '{new_status}'")
                    st.rerun()

    finally:
        db.close()

# -------------------------------------------------------------
# TAB 3: AUDIT LOG EXPLORER
# -------------------------------------------------------------
elif active_tab == "📜 Audit Log Explorer":
    st.subheader("Comprehensive Security Audit Trail")
    db = get_db_session()
    try:
        col_f1, col_f2, col_f3 = st.columns(3)
        with col_f1:
            action_search = st.text_input("Filter Action (e.g. LOGIN_FAILED, ACCESS_DENIED)")
        with col_f2:
            ip_search = st.text_input("Filter IP Address")
        with col_f3:
            status_filter = st.selectbox("Status Filter", ["ALL", "SUCCESS", "FAILURE", "DENIED"])

        log_query = db.query(AuditLog)
        if action_search:
            log_query = log_query.filter(AuditLog.action.ilike(f"%{action_search}%"))
        if ip_search:
            log_query = log_query.filter(AuditLog.ip_address.ilike(f"%{ip_search}%"))
        if status_filter != "ALL":
            log_query = log_query.filter(AuditLog.status == status_filter)

        logs = log_query.order_by(AuditLog.timestamp.desc()).limit(200).all()

        if logs:
            data = [{
                "ID": l.id,
                "Timestamp": l.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "Action": l.action,
                "Status": l.status,
                "IP Address": l.ip_address,
                "User ID": l.user_id or "-",
                "Endpoint": l.endpoint,
                "Details": l.details or ""
            } for l in logs]
            st.dataframe(pd.DataFrame(data), use_container_width=True, hide_index=True)
        else:
            st.info("No audit logs match current filters.")
    finally:
        db.close()

# -------------------------------------------------------------
# TAB 4: ATTACK SIMULATION & DEMO LAB
# -------------------------------------------------------------
elif active_tab == "⚡ Attack Simulation Lab":
    st.subheader("Security Attack Simulation & Defense Verification")
    st.markdown("""
    Trigger realistic IAM threat scenarios from a single interface to verify that AuthShield's
    detection engine, audit logging, and alerting mechanisms trigger according to PRD requirements.
    """)

    db = get_db_session()
    try:
        c1, c2 = st.columns(2)

        with c1:
            st.markdown("#### Scenario A: Brute-Force Login Attack")
            st.caption("Fires 5 failed login attempts from `10.0.0.15` within seconds.")
            if st.button("🚀 Trigger Scenario A (Brute Force)"):
                sim_ip = "10.0.0.15"
                for i in range(5):
                    AuditService.log_event(
                        db=db,
                        action="LOGIN_FAILED",
                        endpoint="/auth/login",
                        status="FAILURE",
                        ip_address=sim_ip,
                        details=f"Simulation: invalid password attempt #{i+1}"
                    )
                    alert = DetectionEngine.on_login_failed(db, ip_address=sim_ip)
                if alert:
                    st.error(f"🚨 Rule Triggered! Alert generated: {alert.alert_type} ({alert.severity}) from {sim_ip}")
                else:
                    st.warning("Attempts recorded; alert may have already triggered in this window.")

            st.markdown("---")

            st.markdown("#### Scenario B: Low-Volume Failed Login (Below Threshold)")
            st.caption("Fires 2 failed login attempts from `10.0.0.20`. Should NOT trigger an alert.")
            if st.button("🚀 Trigger Scenario B (Sub-Threshold)"):
                sim_ip = "10.0.0.20"
                alert_generated = None
                for i in range(2):
                    AuditService.log_event(
                        db=db,
                        action="LOGIN_FAILED",
                        endpoint="/auth/login",
                        status="FAILURE",
                        ip_address=sim_ip,
                        details=f"Simulation: casual typo attempt #{i+1}"
                    )
                    alert_generated = DetectionEngine.on_login_failed(db, ip_address=sim_ip)
                if alert_generated is None:
                    st.success(f"✅ Safe: 2 failed logins logged for {sim_ip}. No alert triggered (threshold is 5).")

        with c2:
            st.markdown("#### Scenario C: Repeated Unauthorized Access")
            st.caption("Fires 3 unauthorized access attempts (`ACCESS_DENIED`) from IP `192.168.1.50`.")
            if st.button("🚀 Trigger Scenario C (Unauthorized Access)"):
                sim_ip = "192.168.1.50"
                for i in range(3):
                    AuditService.log_event(
                        db=db,
                        action="ACCESS_DENIED",
                        endpoint="/users",
                        status="DENIED",
                        ip_address=sim_ip,
                        details=f"Simulation: standard user attempted admin endpoint #{i+1}"
                    )
                    alert = DetectionEngine.on_access_denied(db, ip_address=sim_ip)
                if alert:
                    st.warning(f"🚨 Rule Triggered! Alert: {alert.alert_type} ({alert.severity}) from {sim_ip}")

            st.markdown("---")

            st.markdown("#### Scenario D: Privilege Escalation Alert")
            st.caption("Simulates an administrator elevating a standard user to Admin.")
            if st.button("🚀 Trigger Scenario D (Privilege Escalation)"):
                user = db.query(User).filter(User.username == "user").first()
                admin = db.query(User).filter(User.username == "admin").first()
                if user and admin:
                    alert = DetectionEngine.on_role_changed(
                        db=db,
                        target_user_id=user.id,
                        target_username=user.username,
                        old_role="user",
                        new_role="admin",
                        admin_id=admin.id,
                        admin_ip="192.168.1.100"
                    )
                    if alert:
                        st.error(f"🚨 Privilege Escalation Alert: {alert.alert_type} ({alert.severity})")

            st.markdown("---")

            st.markdown("#### Scenario E: Disabled Account Authentication Attempt")
            st.caption("Simulates login against a disabled account.")
            if st.button("🚀 Trigger Scenario E (Disabled Account)"):
                disabled_user = db.query(User).filter(User.status == "disabled").first()
                if disabled_user:
                    alert = DetectionEngine.on_disabled_account_attempt(
                        db=db,
                        user_id=disabled_user.id,
                        username=disabled_user.username,
                        ip_address="172.16.0.42"
                    )
                    AuditService.log_event(
                        db=db,
                        action="LOGIN_ATTEMPT_DISABLED_ACCOUNT",
                        endpoint="/auth/login",
                        status="FAILURE",
                        ip_address="172.16.0.42",
                        user_id=disabled_user.id,
                        details="Simulation: login attempt against disabled account"
                    )
                    st.error(f"🚨 Disabled Account Alert: {alert.alert_type} ({alert.severity})")
    finally:
        db.close()
