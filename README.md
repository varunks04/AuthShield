# 🛡️ AuthShield — Identity & Security Monitoring Platform

> **A security-focused backend providing JWT authentication, server-side Role-Based Access Control (RBAC), security audit logging, IP-aware request monitoring, rule-based threat detection, alert triage workflows, and an interactive security operations dashboard.**

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

---

## 🚀 5. Quickstart & Installation

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

## 🧪 6. Automated Testing & Verification

### Run Pytest Suite
Run the 25 comprehensive automated tests covering authentication, authorization, detection rules, and alert triage:
```bash
python -m pytest -v
```

### Run with Coverage
```bash
python -m pytest --cov=app tests/
```
*(Demonstrates 90%+ code coverage across the entire application).*

---

## ⚡ 7. Reproducible Attack Simulation (Single Machine)

You can simulate realistic multi-IP cyber attacks from a single computer using the automated simulation runner:
```bash
python scripts/simulate_attacks.py
```

### Scenarios Tested in Simulation:
- **Scenario A**: 5 failed logins from simulated IP `10.0.0.15` $\rightarrow$ Triggers `BRUTE_FORCE_LOGIN` alert.
- **Scenario B**: 2 failed logins from simulated IP `10.0.0.20` $\rightarrow$ Below threshold, no alert generated.
- **Scenario C**: Standard user attempts admin-only endpoints $\rightarrow$ Generates `ACCESS_DENIED` and triggers `REPEATED_UNAUTHORIZED_ACCESS` alert.
- **Scenario D**: Administrator elevates user to admin $\rightarrow$ Triggers `PRIVILEGE_CHANGE` alert.
- **Scenario E**: Authentication attempt on disabled user $\rightarrow$ Denies access and triggers `LOGIN_ATTEMPT_DISABLED_ACCOUNT` alert.

---

## 📊 8. Security Monitoring Dashboard

Launch the Streamlit SOC monitoring dashboard:
```bash
python -m streamlit run dashboard/app.py
```

### Dashboard Capabilities:
1. **Overview & Metrics**: Live KPIs for total users, failed logins, active security events, open alerts, and high-severity issues.
2. **Visualizations**: Alerts by severity, authentication outcomes (success vs. failure), and top suspicious source IPs.
3. **Alert Triage Queue**: Investigate alerts and update statuses (`OPEN` $\rightarrow$ `INVESTIGATING` $\rightarrow$ `RESOLVED` / `FALSE_POSITIVE`).
4. **Audit Log Explorer**: Search and filter security events by action, IP address, and status.
5. **Attack Simulation Lab**: One-click attack triggers directly in the browser to demo detection in real-time.

---

## 🌐 9. Running the REST API Server

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
