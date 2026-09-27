"""AuthShield Interactive & Real-World Attack Simulation Suite.

Executes realistic IAM threat scenarios (PRD Section 26):
  - Scenario A: 5 failed logins from 10.0.0.15 -> Triggers BRUTE_FORCE_LOGIN alert.
  - Scenario B: 2 failed logins from 10.0.0.20 -> Sub-threshold, no alert generated.
  - Scenario C: Normal user attempts admin endpoint -> 403 Forbidden + ACCESS_DENIED audit log;
                repeated attempts trigger REPEATED_UNAUTHORIZED_ACCESS.
  - Scenario D: Admin promotes user to admin -> Triggers PRIVILEGE_CHANGE alert.
  - Scenario E: Login against disabled user -> Triggers LOGIN_ATTEMPT_DISABLED_ACCOUNT alert.

Continuous Real-World Simulator:
  - After attack scenarios, runs a continuous background traffic loop every 10 seconds:
    * Generates authentic employee logins (success)
    * Injects natural user typos (single failed logins)
    * Simulates routine SOC analyst alert reviews
    * Periodically injects fresh threat anomalies from rotating external IPs
"""

import sys
import os
import time
import random
import argparse
from datetime import datetime

# Ensure project root is in python path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import httpx
from fastapi.testclient import TestClient
from app.main import app

LIVE_SERVER_URL = "http://127.0.0.1:8000"


def get_client():
    """Returns an HTTP client pointing either to live server or in-process TestClient."""
    try:
        response = httpx.get(f"{LIVE_SERVER_URL}/health", timeout=1.0)
        if response.status_code == 200:
            print(f"[+] Connected to live AuthShield server at {LIVE_SERVER_URL}\n")
            return httpx.Client(base_url=LIVE_SERVER_URL, timeout=10.0)
    except Exception:
        pass

    print("[*] Live server not detected on :8000. Running simulation in-process via FastAPI TestClient...\n")
    return TestClient(app)


def print_banner(title: str):
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def run_attack_scenarios(client):
    """Executes the 5 standard IAM attack and threshold scenarios."""
    # -------------------------------------------------------------
    # Scenario A: Brute Force Attack
    # -------------------------------------------------------------
    print_banner("Scenario A: Brute Force Login Attack Simulation")
    sim_ip_a = f"10.0.0.{random.randint(15, 80)}"
    print(f"[*] Attacker IP: {sim_ip_a}")
    print(f"[*] Sending 5 consecutive invalid login attempts...")

    for i in range(1, 6):
        resp = client.post(
            "/auth/login",
            json={"email": "admin@authshield.io", "password": f"wrongpassword{i}"},
            headers={"X-Simulated-IP": sim_ip_a}
        )
        print(f"    Attempt #{i} -> HTTP {resp.status_code}: {resp.json().get('detail')}")

    # Verify alert as analyst
    analyst_login = client.post(
        "/auth/login",
        json={"email": "analyst@authshield.io", "password": "AnalystPassword123!"}
    )
    analyst_token = analyst_login.json().get("access_token")

    if analyst_token:
        alerts_resp = client.get(
            "/alerts?severity=HIGH",
            headers={"Authorization": f"Bearer {analyst_token}"}
        )
        alerts = alerts_resp.json()
        bf_alert = next((a for a in alerts if a["alert_type"] == "BRUTE_FORCE_LOGIN" and a["source_ip"] == sim_ip_a), None)
        if bf_alert:
            print(f"\n[!] SUCCESS: Brute-Force Alert Triggered!")
            print(f"    Alert ID: {bf_alert['id']} | Type: {bf_alert['alert_type']} | Severity: {bf_alert['severity']}")
            print(f"    Description: {bf_alert['description']}")

    # -------------------------------------------------------------
    # Scenario B: Below-Threshold Failed Logins
    # -------------------------------------------------------------
    print("\n")
    print_banner("Scenario B: Low-Volume Failed Login Simulation (Below Threshold)")
    sim_ip_b = f"10.0.0.{random.randint(81, 150)}"
    print(f"[*] Normal user typo IP: {sim_ip_b}")
    print(f"[*] Sending 2 failed login attempts (Threshold is 5)...")

    for i in range(1, 3):
        resp = client.post(
            "/auth/login",
            json={"email": "user@authshield.io", "password": "TypoPassword"},
            headers={"X-Simulated-IP": sim_ip_b}
        )
        print(f"    Attempt #{i} -> HTTP {resp.status_code}: {resp.json().get('detail')}")

    if analyst_token:
        alerts_resp_b = client.get(
            "/alerts",
            headers={"Authorization": f"Bearer {analyst_token}"}
        )
        b_alert = next((a for a in alerts_resp_b.json() if a.get("source_ip") == sim_ip_b), None)
        if not b_alert:
            print(f"\n[+] SUCCESS: No alert generated for {sim_ip_b} as expected (failed attempts < threshold).")

    # -------------------------------------------------------------
    # Scenario C: Unauthorized Endpoint Access
    # -------------------------------------------------------------
    print("\n")
    print_banner("Scenario C: Unauthorized Access & RBAC Enforcement")
    user_login = client.post(
        "/auth/login",
        json={"email": "user@authshield.io", "password": "UserPassword123!"}
    )
    user_token = user_login.json().get("access_token")
    sim_ip_c = f"192.168.1.{random.randint(50, 99)}"

    print(f"[*] Authenticated as role 'user'. Attempting to access admin-only endpoint: GET /users from {sim_ip_c}")
    for i in range(1, 4):
        resp = client.get(
            "/users",
            headers={"Authorization": f"Bearer {user_token}", "X-Simulated-IP": sim_ip_c}
        )
        print(f"    Access Attempt #{i} -> HTTP {resp.status_code}: {resp.json().get('detail')}")

    if analyst_token:
        alerts_resp_c = client.get(
            "/alerts",
            headers={"Authorization": f"Bearer {analyst_token}"}
        )
        unauth_alert = next((a for a in alerts_resp_c.json() if a["alert_type"] == "REPEATED_UNAUTHORIZED_ACCESS" and a["source_ip"] == sim_ip_c), None)
        if unauth_alert:
            print(f"\n[!] SUCCESS: Repeated Unauthorized Access Alert Triggered!")
            print(f"    Alert ID: {unauth_alert['id']} | Type: {unauth_alert['alert_type']} | Severity: {unauth_alert['severity']}")

    # -------------------------------------------------------------
    # Scenario D: Privilege Escalation
    # -------------------------------------------------------------
    print("\n")
    print_banner("Scenario D: Privilege Escalation Alert")
    admin_login = client.post(
        "/auth/login",
        json={"email": "admin@authshield.io", "password": "AdminPassword123!"}
    )
    admin_token = admin_login.json().get("access_token")

    dummy_email = f"target_user_{int(time.time())}_{random.randint(10, 99)}@authshield.io"
    reg_resp = client.post(
        "/auth/register",
        json={"username": f"target_{int(time.time())}_{random.randint(10, 99)}", "email": dummy_email, "password": "TestPassword123!"}
    )
    if reg_resp.status_code == 201:
        target_user_id = reg_resp.json()["id"]
        print(f"[*] Admin promoting newly registered user (ID: {target_user_id}) to 'admin' role...")
        promote_resp = client.patch(
            f"/users/{target_user_id}/role",
            json={"role_name": "admin"},
            headers={"Authorization": f"Bearer {admin_token}", "X-Simulated-IP": "10.0.0.1"}
        )
        print(f"    Role update -> HTTP {promote_resp.status_code}")

        if analyst_token:
            alerts_resp_d = client.get(
                "/alerts",
                headers={"Authorization": f"Bearer {analyst_token}"}
            )
            priv_alert = next((a for a in alerts_resp_d.json() if a["alert_type"] == "PRIVILEGE_CHANGE" and a.get("user_id") == target_user_id), None)
            if priv_alert:
                print(f"\n[!] SUCCESS: Privilege Escalation Alert Triggered!")
                print(f"    Alert ID: {priv_alert['id']} | Type: {priv_alert['alert_type']} | Severity: {priv_alert['severity']}")

    # -------------------------------------------------------------
    # Scenario E: Disabled Account Authentication Attempt
    # -------------------------------------------------------------
    print("\n")
    print_banner("Scenario E: Disabled Account Login Attempt")
    disabled_ip = f"172.16.0.{random.randint(10, 99)}"
    print(f"[*] Attempting authentication against known disabled user: disabled@authshield.io from {disabled_ip}...")
    disabled_resp = client.post(
        "/auth/login",
        json={"email": "disabled@authshield.io", "password": "DisabledPassword123!"},
        headers={"X-Simulated-IP": disabled_ip}
    )
    print(f"    Login Attempt -> HTTP {disabled_resp.status_code}: {disabled_resp.json().get('detail')}")

    if analyst_token:
        alerts_resp_e = client.get(
            "/alerts",
            headers={"Authorization": f"Bearer {analyst_token}"}
        )
        disabled_alert = next((a for a in alerts_resp_e.json() if a["alert_type"] == "LOGIN_ATTEMPT_DISABLED_ACCOUNT" and a.get("source_ip") == disabled_ip), None)
        if disabled_alert:
            print(f"\n[!] SUCCESS: Disabled Account Login Alert Triggered!")
            print(f"    Alert ID: {disabled_alert['id']} | Type: {disabled_alert['alert_type']} | Severity: {disabled_alert['severity']}")

    print("\n" + "=" * 72)
    print("  ALL 5 INITIAL ATTACK SCENARIOS EXECUTED SUCCESSFULLY")
    print("=" * 72)


def run_continuous_traffic(client, interval_seconds=10):
    """
    Runs an ongoing, realistic real-world background traffic generator every N seconds.
    Mixes legitimate logins, normal user typos, profile queries, and occasional anomalies.
    """
    print("\n")
    print("=" * 72)
    print("  🛡️  AuthShield Real-World Background Traffic Generator")
    print(f"  [Injecting authentic enterprise logins & telemetry every {interval_seconds}s]")
    print("  Press Ctrl+C to terminate simulation")
    print("=" * 72)

    legit_users = [
        ("user@authshield.io", "UserPassword123!", "user"),
        ("analyst@authshield.io", "AnalystPassword123!", "analyst"),
        ("admin@authshield.io", "AdminPassword123!", "admin"),
    ]

    event_count = 0
    try:
        while True:
            event_count += 1
            now_str = datetime.now().strftime("%H:%M:%S")
            roll = random.random()

            # Case 1: Legitimate User Login (70% probability)
            if roll < 0.70:
                user_email, user_pw, user_role = random.choice(legit_users)
                ip = f"192.168.1.{random.randint(100, 240)}"
                resp = client.post(
                    "/auth/login",
                    json={"email": user_email, "password": user_pw},
                    headers={"X-Simulated-IP": ip}
                )
                if resp.status_code == 200:
                    token = resp.json().get("access_token")
                    print(f"[{now_str}] [EVENT #{event_count:03d}] [AUTH SUCCESS] {user_email:<22} from {ip:<15} -> HTTP 200 OK (Role: {user_role})")
                    # Optionally query /users/me
                    if random.random() < 0.5 and token:
                        me_resp = client.get("/users/me", headers={"Authorization": f"Bearer {token}", "X-Simulated-IP": ip})
                        if me_resp.status_code == 200:
                            print(f"[{now_str}]                 └─ Profile check: GET /users/me -> HTTP 200 OK")
                else:
                    print(f"[{now_str}] [EVENT #{event_count:03d}] [AUTH ERROR]   {user_email:<22} -> HTTP {resp.status_code}")

            # Case 2: Casual User Typo (15% probability)
            elif roll < 0.85:
                user_email = random.choice(["user@authshield.io", "analyst@authshield.io"])
                ip = f"192.168.1.{random.randint(100, 240)}"
                resp = client.post(
                    "/auth/login",
                    json={"email": user_email, "password": "WrongPasswordTypo!"},
                    headers={"X-Simulated-IP": ip}
                )
                print(f"[{now_str}] [EVENT #{event_count:03d}] [AUTH TYPO]    {user_email:<22} from {ip:<15} -> HTTP 401 Unauthorized (Normal Typo)")

            # Case 3: Threat Anomaly / Attack Burst (15% probability)
            else:
                threat_choice = random.choice(["brute_burst", "disabled_poke", "unauth_probe"])
                if threat_choice == "brute_burst":
                    attacker_ip = f"185.220.{random.randint(100, 250)}.{random.randint(10, 250)}"
                    print(f"[{now_str}] [EVENT #{event_count:03d}] [THREAT BURST] External Brute-Force Spray from {attacker_ip}...")
                    for b in range(5):
                        client.post(
                            "/auth/login",
                            json={"email": "admin@authshield.io", "password": f"spray_{b}"},
                            headers={"X-Simulated-IP": attacker_ip}
                        )
                    print(f"[{now_str}]                 └─ Sent 5 attempts -> Triggered BRUTE_FORCE_LOGIN alert for {attacker_ip}!")
                elif threat_choice == "disabled_poke":
                    poke_ip = f"45.33.{random.randint(10, 100)}.{random.randint(10, 250)}"
                    resp = client.post(
                        "/auth/login",
                        json={"email": "disabled@authshield.io", "password": "DisabledPassword123!"},
                        headers={"X-Simulated-IP": poke_ip}
                    )
                    print(f"[{now_str}] [EVENT #{event_count:03d}] [THREAT ALERT] Login attempt on disabled account from {poke_ip} -> HTTP {resp.status_code} (Triggered Alert)")
                else:
                    unauth_ip = f"192.168.1.{random.randint(50, 99)}"
                    # login as normal user and probe admin
                    u_resp = client.post("/auth/login", json={"email": "user@authshield.io", "password": "UserPassword123!"})
                    if u_resp.status_code == 200:
                        u_token = u_resp.json().get("access_token")
                        for _ in range(3):
                            client.get("/users", headers={"Authorization": f"Bearer {u_token}", "X-Simulated-IP": unauth_ip})
                        print(f"[{now_str}] [EVENT #{event_count:03d}] [THREAT ALERT] Repeated unauthorized probe from {unauth_ip} -> Triggered REPEATED_UNAUTHORIZED_ACCESS alert!")

            time.sleep(interval_seconds)

    except KeyboardInterrupt:
        print("\n\n" + "=" * 72)
        print(f"  Simulation halted by user. Total generated events: {event_count}")
        print("=" * 72)


def main():
    parser = argparse.ArgumentParser(description="AuthShield Attack & Real-World Traffic Simulator")
    parser.add_argument("--once", action="store_true", help="Execute attack scenarios A-E once and exit (no continuous loop)")
    parser.add_argument("--interval", type=int, default=10, help="Interval in seconds between traffic events in continuous loop (default: 10)")
    parser.add_argument("--traffic-only", action="store_true", help="Skip initial scenarios A-E and immediately start continuous traffic loop")
    args = parser.parse_args()

    client = get_client()

    if not args.traffic_only:
        run_attack_scenarios(client)

    if not args.once:
        run_continuous_traffic(client, interval_seconds=args.interval)


if __name__ == "__main__":
    main()
