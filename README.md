# 🛡️ AuthShield — Identity & Security Monitoring Platform

> **A security-focused backend providing JWT authentication, server-side Role-Based Access Control (RBAC), security audit logging, IP-aware request monitoring, rule-based threat detection, alert triage workflows, and an interactive security operations dashboard.**

<p align="left">
  <a href="docs/VISUAL_TOUR.md">
    <img src="https://img.shields.io/badge/📸%20Visual%20Product%20Tour-Explore%20Screenshots-0284c7?style=for-the-badge&logo=camera&logoColor=white" alt="Visual Product Tour" />
  </a>
  <a href="LOGICAL_FLOW.md">
    <img src="https://img.shields.io/badge/🧬%20Complete%20Logical%20Flow-Deep%20Dive-10b981?style=for-the-badge&logo=gitbook&logoColor=white" alt="Logical Flow" />
  </a>
  <a href="docs/RUN_GUIDE.md">
    <img src="https://img.shields.io/badge/🚀%20One--Click%20Launchers-Run%20Guide-f59e0b?style=for-the-badge&logo=powershell&logoColor=white" alt="Run Guide" />
  </a>
</p>

---

## 📌 1. Overview & Problem Solved

Modern web applications frequently implement authentication but lack visibility into what happens **after and around authentication**:
- *Who authenticated successfully, and who is failing repeatedly?*
- *Where are requests originating, and are distributed or burst attacks occurring?*
- *Did an unauthorized user attempt to invoke administrative APIs?*
- *Was an account disabled due to compromise, yet credentials are still being attempted?*
- *Did a user suddenly receive elevated administrative permissions?*

**AuthShield** combines identity management (IAM) with security monitoring into a clean, defensive architecture designed to be fully testable, demonstrable, and defensible in technical security engineering interviews.

---

## 📚 Architectural & Operational Documentation Hub

All detailed operational guides, product logic flows, and specifications are organized inside [`docs/`](docs/) and the project root:

| Document | File Path | Focus & Purpose |
| :--- | :--- | :--- |
| **📸 Visual Product Tour** | [`docs/VISUAL_TOUR.md`](docs/VISUAL_TOUR.md) | **Chronological step-by-step visual tour of all dashboard tabs, live AI telemetry, and containment actions** |
| **🧬 Complete Logical Flow** | [`LOGICAL_FLOW.md`](LOGICAL_FLOW.md) | Comprehensive system architecture, exact mathematical formulas, threat detection rules, and Mermaid flowcharts |
| **🚀 Execution & Run Guide** | [`docs/RUN_GUIDE.md`](docs/RUN_GUIDE.md) | One-click launchers (`run_all.bat` / `.ps1` / `.sh`), service start orders, analyst workflows, cheat sheet & seed credentials |
| **🧬 Real-World Logical & Life Flow** | [`docs/life_logical_flow.md`](docs/life_logical_flow.md) | Real-world human behaviors, operational supervision, unmonitored threat conditions, and situational realities |
| **💼 Project & Business Flow** | [`docs/project_business_flow.md`](docs/project_business_flow.md) | Product identity, business justification, stakeholder personas, data pipeline, and enterprise ROI |
| **📋 PRD & Technical Specifications** | [`docs/PRD.txt`](docs/PRD.txt) | Detailed engineering requirements, data models, threat detection rules, and security guidelines |

---

## 🏛️ 2. System Architecture

```text
                                  +-----------------------+
                                  | Client / SOC Analyst  |
                                  +-----------+-----------+
                                              |
                          HTTP REST API / Bearer JWT / X-Simulated-IP
                                              |
                                              v
+-----------------------------------------------------------------------------------+
| AuthShield Backend (FastAPI)                                                     |
|                                                                                   |
|  +------------------------+      +-------------------------+                     |
|  | Authentication API     |      | RBAC Authorization      |                     |
|  | - Argon2id Hashing     |      | - Server-Side Roles     |                     |
|  | - Cryptographic JWT    |      | - Endpoint Protection   |                     |
|  +-----------+------------+      +------------+------------+                     |
|              |                                |                                   |
|              +--------------+  +--------------+                                   |
|                             |  |                                                  |
|                             v  v                                                  |
|                  +----------------------+                                         |
|                  | Central Audit Logger |                                         |
|                  | (Actions, IPs, Status|                                         |
|                  +----------+-----------+                                         |
|                             |                                                     |
|                             v                                                     |
|               +----------------------------+                                      |
|               | Rule-Based Detection Engine|                                      |
|               |  - Rule 1: Brute Force     |                                      |
|               |  - Rule 2: Unauth Access   |                                      |
|               |  - Rule 3: Privilege Esc.  |                                      |
|               |  - Rule 4: Disabled Account|                                      |
|               +-------------+--------------+                                      |
|                             | (Generates Alerts)                                  |
|                             v                                                     |
|               +----------------------------+                                      |
|               | Alert Triage & Management  |                                      |
|               | (OPEN -> RESOLVED, etc.)   |                                      |
|               +----------------------------+                                      |
+-----------------------------------------------------------------------------------+
                                      |
                                      v
                      +-------------------------------+
                      | SQLite / PostgreSQL Database  |
                      +-------------------------------+
                                      ^
                                      | Queries DB & Metrics
                      +---------------+---------------+
                      | Streamlit Security Dashboard  |
                      +-------------------------------+
```

---

## 🔒 3. Threat Detection Rules

AuthShield incorporates a deterministic, rule-based detection engine that inspects security events in real-time:

| Rule | Trigger Condition | Event Action | Generated Alert | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **Rule 1: Brute Force** | $\ge 5$ failed logins from same IP within 5 minutes | `LOGIN_FAILED` | `BRUTE_FORCE_LOGIN` | `HIGH` |
| **Rule 2: Repeated Unauthorized Access** | $\ge 3$ forbidden attempts (`403`) from same user/IP within 5 minutes | `ACCESS_DENIED` | `REPEATED_UNAUTHORIZED_ACCESS` | `MEDIUM` |
| **Rule 3: Privilege Escalation** | Administrator modifies a user's role to `admin` | `ROLE_CHANGED` | `PRIVILEGE_CHANGE` | `HIGH` |
| **Rule 4: Disabled Account Login** | Authentication attempt targeting an account with `status == "disabled"` | `LOGIN_ATTEMPT_DISABLED_ACCOUNT` | `LOGIN_ATTEMPT_DISABLED_ACCOUNT` | `HIGH` |

---

## 👥 4. Role-Based Access Control (RBAC) Model

Permissions are enforced **strictly server-side**. Client-supplied roles or frontend checks are never trusted.

| Endpoint | Description | `user` | `analyst` | `admin` |
| :--- | :--- | :---: | :---: | :---: |
| `POST /auth/register` | Account self-registration | Public | Public | Public |
| `POST /auth/login` | Credential verification & JWT issuance | Public | Public | Public |
| `GET /users/me` | View own user profile | ✅ | ✅ | ✅ |
| `PUT /users/me` | Update personal profile details | ✅ | ✅ | ✅ |
| `POST /users/me/password` | Change personal password | ✅ | ✅ | ✅ |
| `GET /users` | List all system users | ❌ | ✅ | ✅ |
| `PATCH /users/{id}/role` | Modify user assigned role | ❌ | ❌ | ✅ |
| `PATCH /users/{id}/status` | Enable or disable user account | ❌ | ❌ | ✅ |
| `GET /audit-logs` | Inspect audit trail with filters | ❌ | ✅ | ✅ |
| `GET /alerts` | View security alerts queue | ❌ | ✅ | ✅ |
| `PATCH /alerts/{id}/status` | Alert triage (`INVESTIGATING`, `RESOLVED`, etc.) | ❌ | ✅ | ✅ |
| `GET /remediation/blocked-ips` | List active quarantined IPs | ❌ | ✅ | ✅ |
| `POST /remediation/block-ip` | Manually block IP from network | ❌ | ✅ | ✅ |
| `POST /remediation/unblock-ip` | Release IP from quarantine | ❌ | ✅ | ✅ |
| `POST /remediation/quarantine-user/{id}` | Suspend compromised account | ❌ | ✅ | ✅ |
| `POST /remediation/restore-user/{id}` | Re-activate user account | ❌ | ❌ | ✅ |

---

## ⚡ 5. One-Click Multi-Terminal Launchers

You can launch all services, simulations, and test suites in separate terminal windows in order with one command:

- **Windows Command Prompt / Double-Click**:
  ```cmd
  run_all.bat
  ```
- **Windows PowerShell**:
  ```powershell
  .\run_all.ps1
  ```
- **Linux / macOS / Git Bash**:
  ```bash
  chmod +x run_all.sh && ./run_all.sh
  ```

---

## 🚀 6. Manual Setup & Installation

### Prerequisites
- Python 3.10+ (Fully tested on Python 3.14)
- Pip

### Setup

1. **Clone the repository and install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Initialize the database & seed accounts**:
   ```bash
   python -m app.database.init_db
   ```

   **Default Seed Accounts**:
   - **Admin**: `admin@authshield.io` / `AdminPassword123!`
   - **Analyst**: `analyst@authshield.io` / `AnalystPassword123!`
   - **User**: `user@authshield.io` / `UserPassword123!`
   - **Disabled User**: `disabled@authshield.io` / `DisabledPassword123!`

---

## 🧪 7. Automated Testing & Verification

### Run Pytest Suite
Run the **29 comprehensive automated tests** covering authentication, authorization, detection rules, alert triage, manual threat containment, and RBAC remediation:
```bash
python -m pytest -v
```

### Run with Coverage
```bash
python -m pytest --cov=app tests/
```
*(Demonstrates **91% code coverage** across all modules in the application).*

---

## ⚡ 8. Reproducible Attack Simulation (Single Machine)

You can simulate realistic multi-IP cyber attacks from a single computer using the automated simulation runner:
```bash
# Run attack scenarios once and verify alerts:
python scripts/simulate_attacks.py --once

# Or run with continuous real-world traffic stream:
python scripts/simulate_attacks.py
```

### Scenarios Tested in Simulation:
- **Scenario A**: 5 failed logins from simulated IP `10.0.0.15` $\rightarrow$ Triggers `BRUTE_FORCE_LOGIN` alert.
- **Scenario B**: 2 failed logins from simulated IP `10.0.0.20` $\rightarrow$ Below threshold, no alert generated.
- **Scenario C**: Standard user attempts admin-only endpoints $\rightarrow$ Generates `ACCESS_DENIED` and triggers `REPEATED_UNAUTHORIZED_ACCESS` alert.
- **Scenario D**: Administrator elevates user to admin $\rightarrow$ Triggers `PRIVILEGE_CHANGE` alert.
- **Scenario E**: Authentication attempt on disabled user $\rightarrow$ Denies access and triggers `LOGIN_ATTEMPT_DISABLED_ACCOUNT` alert.

---

## 📊 9. Security Operations Dashboard

Launch the streamlined Streamlit SOC monitoring dashboard:
```bash
python -m streamlit run dashboard/app.py
```

<p align="center">
  <a href="docs/VISUAL_TOUR.md">
    <img src="https://img.shields.io/badge/📸%20Take%20Guided%20Visual%20Tour-Explore%208%20Chronological%20Screenshots-0284c7?style=for-the-badge&logo=camera&logoColor=white" alt="Guided Visual Tour" />
  </a>
</p>

[![AuthShield SOC Overview Dashboard](assets/screenshots/01_dashboard_overview_telemetry.png)](docs/VISUAL_TOUR.md)

### 📸 Visual Product Tour Highlights ([`docs/VISUAL_TOUR.md`](docs/VISUAL_TOUR.md))
Explore the complete chronological visual walkthrough across all operational stages:
1. **[Live Overview & DEFCON 2 Telemetry](docs/VISUAL_TOUR.md#step-1-soc-overview--live-telemetry)**: Top header indicators, 4 Hero KPI cards, and Groq-powered CISO fleet posture synthesis.
2. **[AI Strategic Recommendations](docs/VISUAL_TOUR.md#step-2-ai-ciso-threat-briefing--strategic-actions)**: Autonomous key findings (alert backlog, concentrated source activity) and remediation playbooks.
3. **[Forensic Visualizations](docs/VISUAL_TOUR.md#step-3-forensic-visualizations--attack-dynamics)**: Altair charts for threat severity distribution, authentication dynamics, and top offender IP rankings.
4. **[Alert Triage & Incident Cards](docs/VISUAL_TOUR.md#step-4-security-incident-investigation--triage-queue)**: Interactive cards with 1-click status transitions, IP quarantine, and deep-dive AI investigations.
5. **[Multi-Model AI Orchestrator](docs/VISUAL_TOUR.md#step-5-ai-threat-intelligence--multi-tier-model-pipeline)**: 3-tier cascade status (Groq 827ms $\rightarrow$ OpenRouter 8386ms $\rightarrow$ Local SOC Heuristics 1ms).
6. **[Active Threat Containment](docs/VISUAL_TOUR.md#step-6-active-defense--perimeter-containment-center)**: Forensic IP dossier inspector, network denylist, and compromised user account lockouts.
7. **[Forensic Audit Trail Explorer](docs/VISUAL_TOUR.md#step-7-forensic-audit-trail--tamper-evident-logs)**: Preset filter pills, multi-parameter search, and CSV export for compliance reporting.
8. **[Attack Simulation Cockpit](docs/VISUAL_TOUR.md#step-8-attack-simulation-lab--traffic-cockpit)**: 5 targeted IAM threat scenarios, live traffic generator, and terminal execution logs.

---

## 🌐 10. Running the REST API Server

Start the FastAPI application with Uvicorn:
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive Swagger API documentation will be available at:
- **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 💼 10. Technical Interview Defense Guide

*When defending AuthShield in a security engineering interview (e.g. Cyderes):*

### Q1: What is the difference between Authentication and Authorization?
> **Authentication (AuthN)** answers *"Who are you?"* by verifying credentials (such as Argon2id password verification) and issuing cryptographic identity tokens (JWT).
> **Authorization (AuthZ)** answers *"What are you allowed to do?"* by taking the authenticated identity, inspecting server-side assigned roles, and enforcing access rules on resources.

### Q2: Why did you enforce RBAC on the server instead of the client?
> A client application (browser, mobile app, API caller) is completely untrusted. Any client-side check can be easily bypassed by inspecting network requests or using tools like cURL/Burp Suite. In AuthShield, every protected endpoint independently queries trusted database records and denies unauthorized roles with `403 Forbidden` and an `ACCESS_DENIED` audit event.

### Q3: How does your brute-force detection work without distributed infrastructure?
> In `app/detection/brute_force.py`, whenever a `LOGIN_FAILED` event is logged, the detection engine performs a sliding window query against the `audit_logs` table for that source IP within the last 300 seconds (`BRUTE_FORCE_WINDOW_SECONDS`). If the count reaches 5 (`BRUTE_FORCE_THRESHOLD`), it generates a `BRUTE_FORCE_LOGIN` alert with `HIGH` severity. It also performs a deduplication check so subsequent attempts in the same window don't produce alert storms.

### Q4: How did you test IP-based detection from a single development laptop?
> We implemented IP extraction that checks `X-Simulated-IP` (in non-production environments) before falling back to `X-Forwarded-For` and client socket IP. This allows deterministic, reproducible attack simulations (e.g., simulating attacks from `10.0.0.15` vs normal typos from `10.0.0.20`) from a single automated test runner or pytest fixture.

---

## 📄 License
MIT License. Built for practical IAM and security engineering demonstration.
