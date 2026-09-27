# 💼 Project & Business Flow — AuthShield

> **Technical product identity, business problem justification, user personas, end-to-end data pipeline, enterprise value propositions, monetization strategy, and engineering roadmap.**

**Documentation Hub:** [📖 Root README](../README.md) • [🚀 Run Guide](RUN_GUIDE.md) • [🧬 Life & Logical Flow](life_logical_flow.md) • [📋 PRD Specification](PRD.txt)

---

## 1. What is the Project?

**AuthShield** is a defensive security and Identity & Access Management (IAM) backend platform combined with a Security Operations Center (SOC) monitoring dashboard and manual threat containment engine. 

It provides cryptographic user authentication (Argon2id + Bearer JWT), strict server-side Role-Based Access Control (RBAC), centralized security audit logging, IP-aware request monitoring, deterministic rule-based threat detection, an interactive triage interface for security analysts, and active network quarantine capabilities.

```text
+-----------------------------------------------------------------------------------+
| AuthShield Platform                                                               |
|                                                                                   |
|  [ Identity & Access (IAM) ]           [ Security Operations Center (SOC) ]        |
|  - Argon2id Password Hashing           - Real-time Audit Trail Explorer           |
|  - Cryptographic JWT Bearer Tokens     - Sliding-Window Threat Engine (4 Rules)   |
|  - Server-Enforced RBAC Layer          - Centralized Incident Action Center       |
|  - Dynamic IP Tracking & Simulation    - Streamlit Live Metrics & Visualizations  |
|                                                                                   |
|  [ Active Defense & Containment ]      [ Automated Test & Simulation Suite ]      |
|  - Manual IP Denylist (HTTP 403)       - 29 Automated Tests (91% Coverage)        |
|  - Account Lockdown & Restoration      - Multi-Scenario Traffic Generator         |
|  - REST Remediation API Endpoints      - One-Click Multi-Terminal Launchers       |
+-----------------------------------------------------------------------------------+
```

---

## 2. What Problem Does It Solve?

### The Core Problem: The Post-Authentication Blindspot
Modern web applications almost universally implement authentication (e.g., login screens, password forms). However, virtually all of them suffer from total blindness **after and around authentication**:
- When credentials fail, who failed? Was it a single typo or a 500-request credential-stuffing attack?
- Where are requests originating from? Is one foreign IP spraying dozens of employee accounts?
- Did an authenticated user probe endpoints they lack permission for?
- When an administrator grants someone full administrative privileges, who saw it, and who verified it?
- When an employee is terminated and their account is marked `disabled`, are adversaries still attempting to use their leaked credentials across other systems?

AuthShield solves this by unifying **Identity Management** with **Security Monitoring** into a cohesive defensive perimeter.

---

## 3. Why is this Problem Important?

### Consequences of Not Solving It:
1. **Undetected Account Takeovers (ATO):** Without rate-aware sliding window detection, brute-force attacks succeed silently without anyone noticing until sensitive customer data is on the dark web.
2. **Untrusted Client Bypasses:** Systems that rely on frontend role checks (e.g., hiding an "Admin" button in React/Vue) can be bypassed in seconds using simple tools like Postman, curl, or Burp Suite.
3. **Audit Impossibility During Forensic Investigations:** In the event of a breach, organizations without structured audit tables (`audit_logs`) cannot answer legal inquiries about *what data was touched*, *when*, and *by whom*.
4. **Catastrophic Regulatory Fines:** Non-compliance with standards like SOC2, ISO 27001, HIPAA, and GDPR, all of which mandate immutable access logging, role separation, and suspicious activity detection.
5. **Insider Privilege Creep:** Untracked role changes allow rogue administrators or compromised internal accounts to quietly grant backdoor admin roles to secondary accounts.

---

## 4. Who Are the Users?

```text
                                 AUTOSHIELD USERS
                                        │
           ┌────────────────────────────┴────────────────────────────┐
           ▼                                                         ▼
    PRIMARY USERS                                             SECONDARY USERS
 1. Standard End User (Client / Employee)                 1. Compliance Officers & Auditors
 2. Security Analyst (SOC Operator)                       2. Executive Leadership (CISO, CTO)
 3. System Administrator (IT / SecOps)                    3. Incident Response Teams
```

### Primary Users:
- **Standard User (`user` role):** Needs seamless, friction-free login, secure password updating, profile management, and zero credential leakage.
- **Security Analyst (`analyst` role):** Responsible for 24/7 monitoring. Investigates security alerts, examines client IP telemetry, filters audit logs, and transitions alert statuses (`OPEN` $\rightarrow$ `INVESTIGATING` $\rightarrow$ `RESOLVED` / `FALSE_POSITIVE`).
- **System Administrator (`admin` role):** Governs user lifecycles. Can view all users, promote or demote user roles, deactivate/enable accounts, and modify system settings.

### Secondary Users:
- **Compliance Auditors:** Review tamper-evident audit logs to verify role segregation and access enforcement.
- **CISO / Security Managers:** Review dashboard KPIs (failed login trends, open vs. resolved incident ratios, top attacker IPs) to allocate defensive budgets.

---

## 5. How Does the Project Work? (End-to-End Pipeline)

```text
[ USER / CLIENT ]
       │
       ▼ (1) HTTP Request (JSON Body, Authorization Header, X-Simulated-IP)
[ FASTAPI INGESTION LAYER ]
       │
       ▼ (2) Input Validation (Pydantic Schemas: Auth, User, Alert)
[ SECURITY & AUTH ENGINE ]
       │─── Argon2id Hashing Check (app/auth/password.py)
       │─── JWT Bearer Token Verification & Role Extraction (app/auth/jwt.py)
       └─── Server-Side RBAC Guard (app/auth/permissions.py)
       │
       ▼ (3) Centralized Audit Dispatcher
[ AUDIT LOG SERVICE ]
       │─── Writes immutable event record (action, user, IP, timestamp, details)
       └─── Commits to Database (authshield.db)
       │
       ▼ (4) Real-Time Detection Engine Evaluation
[ DETECTION ENGINE ]
       ├── Rule 1: Sliding Window >= 5 failed logins within 5 mins -> BRUTE_FORCE_LOGIN (HIGH)
       ├── Rule 2: Sliding Window >= 3 403-Forbidden within 5 mins  -> REPEATED_UNAUTHORIZED_ACCESS (MED)
       ├── Rule 3: Role changed to 'admin'                         -> PRIVILEGE_CHANGE (HIGH)
       └── Rule 4: Login attempt on disabled user                  -> LOGIN_ATTEMPT_DISABLED_ACCOUNT (HIGH)
       │
       ▼ (5) Alert Persistence & Triage Queue
[ SECURITY ALERTS TABLE ]
       │─── Deduplication check prevents alert storms
       └─── Assigns OPEN status and severity level
       │
       ▼ (6) Consumed By Frontends
[ SOC DASHBOARD & CLIENT RESPONSES ]
       ├── REST API returns JWT / Profile / Resource / Error to Client
       └── Streamlit UI updates live metrics, charts, and triage queue for Analyst
```

---

## 6. What Value Does It Provide?

| Value Category | Concrete Benefit in AuthShield |
| :--- | :--- |
| **Saves Time** | Automated rule detection alerts analysts immediately; no manual parsing of gigabytes of raw text log files required. |
| **Reduces Breach Cost** | Catches credential attacks in the first 5 minutes rather than the industry average of 200+ days. |
| **Automates Work** | Real-time sliding window queries eliminate human log monitoring; deduplication prevents alert noise and fatigue. |
| **Improves Decision-Making** | Analysts have full contextual data on one screen: offending IP, affected user, exact timestamp, and prior audit events. |
| **Enforces Least Privilege** | Replaces porous client-side checks with rock-solid server-side dependency injection (`require_roles("admin")`). |

---

## 7. Possible Business Model

AuthShield is architected for deployment as a dedicated security microservice or a commercial B2B product:

```text
                                BUSINESS MODEL
                                      │
         ┌────────────────────────────┼────────────────────────────┐
         ▼                            ▼                            ▼
 [ B2B SaaS Tier ]          [ Enterprise Dedicated ]     [ Managed SOC Service (MSSP) ]
 - Per-seat pricing for      - On-prem / Private cloud    - Turnkey IAM + human analyst
   analysts & admins           deployment                   triage bundle for startups
 - Tiered by event volume    - Custom SIEM connectors     - White-label security
   (e.g., $99/mo up to         (Splunk, Datadog)            operations center
   100k audit events)        - Dedicated SLA support
```

### 1. Pricing Strategy:
- **Tier 1 (Startup / Small App):** Up to 5,000 active identities, 50,000 monthly audit events, community dashboard access ($49/month).
- **Tier 2 (Growth Enterprise):** Unlimited identities, multi-seat SOC analyst dashboards, custom detection threshold tuning, 90-day log retention ($299/month).
- **Tier 3 (Enterprise / MSSP):** Air-gapped on-premise deployments, automated webhook escalation (Slack, PagerDuty), dedicated compliance exports.

### 2. Market Fit:
Mid-market companies that cannot afford million-dollar Splunk/CrowdStrike enterprise contracts but must pass SOC2 and ISO compliance requirements.

---

## 8. Future Engineering Scope & Roadmap

```text
                                 ROADMAP
                                    │
    ┌──────────────────────┬────────┴─────────────┬─────────────────────┐
    ▼                      ▼                      ▼                     ▼
[ Phase 1: Storage ]   [ Phase 2: IAM ]       [ Phase 3: AI/Ops ]   [ Phase 4: Integrations ]
- PostgreSQL pooling   - Time-based MFA       - Baseline anomaly    - PagerDuty & Slack
- Redis caching for      (TOTP / Authenticator) detection algorithms   webhooks
  sliding windows      - Password reset       - Risk scoring engine - Splunk / SIEM
- Log archiving / S3     workflows via email    per request IP        syslog forwarder
```

1. **Database & Cache Scaling:**
   - Migrate in-memory sliding window checks to high-speed **Redis sliding window logs** for millions of requests/second.
   - Dedicated PostgreSQL partitioned tables for multi-year audit log retention.
2. **Enhanced Authentication Capabilities:**
   - Multi-Factor Authentication (MFA / TOTP) support via Google Authenticator.
   - Refresh token rotation with revocation blacklisting in Redis.
3. **Advanced Threat Intelligence & AI:**
   - Geolocation IP enrichment (MaxMind GeoIP) to alert on impossible travel velocity (e.g., login from New York, then London 10 minutes later).
   - Anomaly detection comparing request frequencies against historical baselines.
4. **Enterprise Alert Integrations:**
   - Real-time webhook notifications to Slack channels, Microsoft Teams, and PagerDuty incident queues.
