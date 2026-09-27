# 🛡️ AuthShield — Execution & Run Guide

> **Quick reference guide for launching all components, running attack simulations, running tests, utilizing default credentials, and operating the SOC dashboard.**

**Documentation Hub:** [📖 Root README](../README.md) • [🧬 Life & Logical Flow](life_logical_flow.md) • [💼 Project & Business Flow](project_business_flow.md) • [📋 PRD Specification](PRD.txt)

---

## 🚀 Quick Commands Cheat Sheet

| Purpose | Command | Default Port / URL |
| :--- | :--- | :--- |
| **FastAPI Backend** | `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload` | http://127.0.0.1:8000/docs |
| **Streamlit Dashboard** | `python -m streamlit run dashboard/app.py` | http://localhost:8501 |
| **Attack Simulation** | `python scripts/simulate_attacks.py` | Terminal output |
| **Pytest Test Suite** | `python -m pytest -v` | Terminal output |
| **Pytest Coverage** | `python -m pytest --cov=app tests/` | Terminal output |
| **Database Re-seed** | `python -m app.database.init_db` | SQLite (`authshield.db`) |

---

## ⚡ One-Click Multi-Terminal Launchers

You can launch all services, attack simulations, and test suites in separate terminal windows in order using one command:

### Windows (Command Prompt / Double-Click)
```cmd
:: Run all in recommended dependency order (DB -> Backend -> Dashboard -> Attacks -> Pytest -> Coverage)
run_all.bat

:: Or open interactive selector menu:
run_all.bat --menu

:: Or run core services only:
run_all.bat --services
```

### Windows (PowerShell)
```powershell
# Run all in recommended order
.\run_all.ps1

# Or run core services only
.\run_all.ps1 -Mode Services
```

### Linux / macOS / Git Bash
```bash
# Make executable (if needed) and run
chmod +x run_all.sh
./run_all.sh
```

---

## 1. 🌐 Run the Backend API Server (FastAPI)

Start the REST API server with live reloading enabled:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Endpoints & Documentation:
- **Interactive Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc Documentation**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)
- **Remediation & Containment APIs**:
  - `GET /remediation/blocked-ips`: List all blocked IPs and active status
  - `POST /remediation/block-ip`: Manually block an IP with analyst reason & audit log
  - `POST /remediation/unblock-ip`: Unblock an IP with resolution notes
  - `POST /remediation/quarantine-user/{user_id}`: Lock down a compromised account
  - `POST /remediation/restore-user/{user_id}`: Restore a quarantined account

---

## 2. 📊 Run the Security Operations Dashboard (Streamlit)

Open a new terminal window and launch the SOC analyst interface:

```powershell
python -m streamlit run dashboard/app.py
```

### Features & Simplified Analyst Workflow:
- **Overview & Live Metrics**: Hero KPI cards (Total Events, Failed Auth Ratio, Open Security Alerts, Active Quarantine), Altair threat distribution charts, and Top Suspicious IPs telemetry.
- **Alert Triage Queue**:
  - **Incident Action Center**: Centralized action panel to triage alerts (`INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`, `OPEN`) or enforce containment (`Quarantine IP`, `Quarantine Account`) in one place without repetitive row buttons.
  - **Clean Incident Cards**: Visual incident cards displaying severity, status, timestamps, target entities, and forensic evidence.
  - **Compact Table View**: Full tabular representation with 1-click CSV export.
- **Active Defense & Remediation (Tab 3)**:
  - **Forensic IP Inspector & Dossier**: Look up any IP to examine total events, failed logins, denials, and linked alerts, with 1-click block/unblock.
  - **Network Denylist Manager**: Clean tabular view of quarantined IPs with a single release selector (no per-row buttons) and manual block form.
  - **Account Quarantine Manager**: Clean tabular view of disabled accounts with a single restore selector and manual suspension form.
  - **Remediation Audit Trail**: Real-time audit trail of all manual containment decisions.
- **Audit Log Explorer**: Search and filter audit records by action type, IP address, and status with CSV export.
- **Attack Simulation Lab**: Execute MITRE ATT&CK mapped scenarios (A-E) or stream realistic enterprise login telemetry.

---

## 3. ⚡ Run the Attack Simulation Script

Execute synthetic multi-IP attack patterns from a single machine:

```powershell
python scripts/simulate_attacks.py
```

### Simulated Scenarios:
- **Scenario A (Brute Force Login)**: 5 consecutive failed logins from `10.0.0.15` (triggers `BRUTE_FORCE_LOGIN` alert).
- **Scenario B (Normal Typos)**: 2 failed logins from `10.0.0.20` (below alert threshold).
- **Scenario C (Unauthorized Endpoint Access)**: Standard user invokes admin endpoints (triggers `REPEATED_UNAUTHORIZED_ACCESS` alert).
- **Scenario D (Privilege Escalation)**: Admin elevates user role to `admin` (triggers `PRIVILEGE_CHANGE` alert).
- **Scenario E (Disabled Account Login)**: Attempting login to a disabled account (triggers `LOGIN_ATTEMPT_DISABLED_ACCOUNT` alert).

---

## 4. 🧪 Run Automated Tests

Run the full pytest suite:

```powershell
python -m pytest -v
```

Run test suite with code coverage analysis:

```powershell
python -m pytest --cov=app tests/
```

---

## 5. 🛠️ Initialize or Reset Database & Seed Users

If you need to reset the SQLite database (`authshield.db`) and seed default test accounts:

```powershell
python -m app.database.init_db
```

---

## 🔑 Default Seed Credentials

All accounts are pre-configured with Argon2id hashed passwords:

| Role | Email | Password | Permissions |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin@authshield.io` | `AdminPassword123!` | Full administrative access, user management, audit logs, alert triage |
| **Analyst** | `analyst@authshield.io` | `AnalystPassword123!` | View audit logs, triage alerts, list users |
| **User** | `user@authshield.io` | `UserPassword123!` | Standard user access (`/users/me`) |
| **Disabled User** | `disabled@authshield.io` | `DisabledPassword123!` | Account disabled; login attempts trigger security alerts |
