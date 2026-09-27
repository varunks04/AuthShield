# 🛡️ Real-World Logical & Life Flow — AuthShield

> **Real-world human behaviors, operational supervision, unmonitored threat conditions, situational realities, and ultimate outcomes.**

**Documentation Hub:** [📖 Root README](../README.md) • [🚀 Run Guide](RUN_GUIDE.md) • [💼 Project & Business Flow](project_business_flow.md) • [📋 PRD Specification](PRD.txt)

---

## 1. Main Person / User (The Digital Identity Holder)

### Who is this person?
A standard employee, client, or consumer who needs to interact with an organization's digital portal or protected API.

```text
               [ Real Person / End User ]
                           ↓
     Wants to access their work, data, or tools
                           ↓
     Step 1: Onboard / Register (Name, Email, Secret Password)
                           ↓
     Step 2: Authenticate (Present Email + Password at Front Door)
                           ↓
     Step 3: Receive Pass / Keycard (Cryptographic Bearer JWT Token)
                           ↓
     Step 4: Perform Permitted Tasks (View Profile, Update Data)
```

### What does the person normally do?
1. **Presents Identity Credentials:** Provides their registered email and memorized secret password.
2. **Accepts Security Boundaries:** Operates strictly within their permitted territory (e.g., viewing their own profile, editing personal settings, updating passwords).
3. **Makes Occasional Mistakes:** Occasionally forgets a character or typos their password once or twice, then successfully enters the correct one.

---

## 2. "Parents Present" (Supervised State: Security Analysts & Administrators on Duty)

In real life, when supervisors, guardians, or administrators are actively present, the digital environment has immediate human oversight and governance.

```text
               [ SOC Analyst / System Admin On Duty ]
                                 │
         ┌───────────────────────┼───────────────────────┐
         ▼                       ▼                       ▼
[ Live SOC Dashboard ]  [ Incident Action Center ]  [ Active Threat Containment ]
 - Real-time metrics     - Centralized triage bar    - Manual IP quarantine
 - Auth event dynamics   - Status state-machine      - User account lockdown
 - Top suspicious IPs    - Evidence inspection       - Immediate HTTP 403 block
```

### What happens in this state?
- **Active Oversight:** The Security Operations Center (SOC) analyst sits in front of the live monitoring console ([`dashboard/app.py`](file:///c:/Users/ASUS/Desktop/AuthSheild/dashboard/app.py)), watching authentication flows and IP origins.
- **Explicit Role Governance:** An administrator is the only authority allowed to change who has power in the system. If an employee gets promoted, the administrator formally modifies their role (`PATCH /users/{id}/role`).
- **Account Disablement:** If an employee resigns or a laptop is stolen, the administrator immediately deactivates the account (`PATCH /users/{id}/status` $\rightarrow$ `disabled`).
- **Manual Threat Containment & Isolation:**
  - When observing attacks (e.g. brute force password spraying), the analyst immediately issues a **Manual IP Block** from the Incident Action Center or the Active Defense console.
  - The backend instantly rejects any further TCP/HTTP connections from that source IP with `403 Forbidden` (`BLOCKED_IP_REJECTED`).
  - If user credentials have been leaked, the analyst immediately suspends the target account.
- **Human Triage Workflow:**
  1. An alert is flagged as `OPEN`.
  2. The analyst inspects the source IP, timestamp, and audit trail in the Incident Action Center.
  3. Status moves to `INVESTIGATING`.
  4. If verified as legitimate activity, it is closed as `RESOLVED`.
  5. If an engineer was running benign tests, it is closed as `FALSE_POSITIVE`.

### What does the main user experience?
Prompt support, safe account resets, controlled permission upgrades, and assurance that their data is actively guarded.

---

## 3. "Parents Not Present" (Unsupervised State: The 3:00 AM Scenario & Rogue Actors)

What happens when administrators and security analysts are away from their desks, asleep, or in a different timezone? 

In unprotected systems, the absence of human supervisors leads to silent breaches, data theft, and uninhibited credential stuffing.

```text
                  [ Middle of the Night: 3:00 AM ]
              (No Security Analyst Looking at Screens)
                                 │
             ┌───────────────────┴───────────────────┐
             ▼                                       ▼
     [ Automated Bot Attack ]              [ Rogue Insider Probe ]
  - 100s of rapid login guesses         - Testing forbidden admin APIs
  - Distributed credential stuffing     - Attempting unauthorized escalation
                                 │
                                 ▼
           [ AUTONOMOUS GUARDIAN: AuthShield Engine ]
  - Sliding-window mathematical check over audit log records
  - Autonomous evaluation without human intervention
  - Instant perimeter denial (HTTP 401 / 403)
  - Permanent audit recording + High-Severity Alert queued
```

### What changes when supervisors aren't present?
1. **Attackers take advantage of silence:** Malicious bots launch automated password-spraying scripts.
2. **Disgruntled former employees attempt revenge:** Using previously saved credentials on a disabled account.
3. **Curious or rogue users test their boundaries:** A standard user tries to hit administrative endpoints directly using tools like Postman, curl, or Burp Suite.

### Who takes responsibility?
**The Autonomous Detection & Enforcement Engine:**
- Even with zero humans awake, the backend does not rely on trust.
- Every single request must independently prove its cryptographic validity (JWT validation).
- Every access denial is irrevocably written into the immutable audit database with the client's source IP.
- Pre-configured detection rules calculate sliding-window rates in real time.
- If threshold limits are crossed, high-severity alarms are generated autonomously and locked into the queue for the morning shift.

---

## 4. Different Situations (Real-World Operational Scenarios)

AuthShield models five specific real-world situations with distinct behavioral flows:

```text
                            REAL-WORLD SITUATIONS
                                      │
   ┌───────────────┬──────────────────┼──────────────────┬────────────────┐
   ▼               ▼                  ▼                  ▼                ▼
Situation A    Situation B        Situation C        Situation D      Situation E
Rapid Brute    Human Typo         Curiosity /        Privilege        Zombie Account
Force Attack   (Normal Mistake)   Sneaking Attempt   Escalation       Resurrection
```

### Situation A — The Rapid Brute-Force Password Spray
- **Real-Life Scenario:** An external attacker or botnet at IP `10.0.0.15` has acquired a target username/email and attempts to guess passwords in rapid succession.
- **Flow:**
  1. Attacker sends attempt #1 $\rightarrow$ Fails (`LOGIN_FAILED` logged).
  2. Attacker sends attempt #2, #3, #4 $\rightarrow$ All fail.
  3. Attacker sends attempt #5 within 5 minutes.
  4. The sliding window reaches $\ge 5$ failures for IP `10.0.0.15`.
  5. **Engine Action:** Autonomous creation of a `HIGH` severity `BRUTE_FORCE_LOGIN` alert. Deduplication prevents alert floods while keeping the perimeter closed.

### Situation B — The Benign Human Mistake (Normal User Typo)
- **Real-Life Scenario:** A legitimate employee at IP `10.0.0.20` has Caps Lock on or mistypes their complex password twice before getting it right.
- **Flow:**
  1. User sends attempt #1 $\rightarrow$ Fails (`LOGIN_FAILED` logged).
  2. User sends attempt #2 $\rightarrow$ Fails (`LOGIN_FAILED` logged).
  3. User enters the correct password on attempt #3 $\rightarrow$ Success (`LOGIN_SUCCESS` logged).
  4. **Engine Action:** The failure count (2) is strictly below the threshold (5). The system logs the attempts for audit integrity but **does not** sound a false alarm or wake up the on-call analyst.

### Situation C — The Curious Insider / Boundary Prober
- **Real-Life Scenario:** A standard user with legitimate credentials decides to see if they can access the employee salary list or administrative user registry (`GET /users` or `PATCH /users/{id}/role`).
- **Flow:**
  1. User authenticates legitimately and obtains a valid JWT keycard.
  2. User manually sends requests to `/users` or admin management routes.
  3. The server-side RBAC guard inspects the user's role (`user`). It notices `user` is not in `["admin", "analyst"]`.
  4. The server rejects the request immediately with `403 Forbidden`.
  5. The server writes an `ACCESS_DENIED` event into the audit log.
  6. If the user repeats this 3 or more times within 5 minutes, the system autonomously triggers a `MEDIUM` severity `REPEATED_UNAUTHORIZED_ACCESS` alert.

### Situation D — The Administrative Privilege Escalation
- **Real-Life Scenario:** An administrator elevates a regular contractor or employee (`user@authshield.io`) to have full administrative powers (`admin`).
- **Flow:**
  1. Administrator makes an intentional or compromised API call: `PATCH /users/3/role` with `{"role_name": "admin"}`.
  2. The system executes the database update and commits the role change.
  3. Because promoting an account to `admin` represents the highest potential blast radius in an organization, the system writes a `ROLE_CHANGED` audit log.
  4. **Engine Action:** Autonomously triggers a `HIGH` severity `PRIVILEGE_CHANGE` alert. This ensures peer visibility so no administrator can secretly create shadow admin accounts without an immediate detection record.

### Situation E — The Terminated Employee / Compromised Credential
- **Real-Life Scenario:** An employee was offboarded yesterday, and HR marked their account `disabled`. The employee (or an adversary who stole their password) attempts to log in at 9:00 AM.
- **Flow:**
  1. Offboarded user submits valid historical credentials (`disabled@authshield.io` / `DisabledPassword123!`).
  2. The system locates the account, checks `status`, and observes `status == "disabled"`.
  3. The door is slammed shut: HTTP `403 Forbidden` is returned with `detail: "This account has been disabled. Please contact an administrator."`
  4. The system logs a `LOGIN_ATTEMPT_DISABLED_ACCOUNT` audit event.
  5. **Engine Action:** Immediately triggers a `HIGH` severity alert notifying the SOC that credentials for a dead account are actively in play in the wild.

---

## 5. Final Outcome

What should ultimately happen in the real world when this system operates?

```text
                               FINAL OUTCOME
                                     │
       ┌─────────────────────────────┼─────────────────────────────┐
       ▼                             ▼                             ▼
[ The Attacker ]             [ The Legitimate User ]        [ The Business / SOC ]
- Stopped at the gate        - Enjoys frictionless,         - Complete audit accountability
- Banned by thresholds         predictable access           - Instant visibility on dashboard
- Leaves zero footprint      - Protected from account       - Triage queue resolved cleanly
  inside protected data        takeover & tampering         - Regulatory compliance achieved
```

1. **Zero Trust at All Times:** A valid password gets you through the front door, but never lets you roam into rooms you do not belong in.
2. **Defensible Audit Trail:** Every action has a timestamp, user ID, endpoint, outcome, and client IP recorded permanently.
3. **No Alert Fatigue:** Distinguishes between everyday human typos (2 failed attempts) and targeted attacks (5+ attempts).
4. **Resolution & Peace of Mind:** Security analysts start their shift with clean, prioritized alerts with complete contextual breadcrumbs to resolve incidents or clear false positives with confidence.
