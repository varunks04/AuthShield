"""Detection Engine Rule Tests (PRD Section 25)."""


def test_four_failed_logins_triggers_no_alert(client, analyst_token):
    """4 failed logins should remain below threshold (5) and not produce an alert."""
    test_ip = "192.168.10.1"
    for i in range(4):
        client.post(
            "/auth/login",
            json={"email": "user@authshield.io", "password": f"wrong{i}"},
            headers={"X-Simulated-IP": test_ip}
        )

    alerts_resp = client.get(
        "/alerts",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    alerts = alerts_resp.json()
    bf_alerts = [a for a in alerts if a["source_ip"] == test_ip]
    assert len(bf_alerts) == 0


def test_five_failed_logins_triggers_brute_force_alert(client, analyst_token):
    """5 failed logins from same IP should trigger a BRUTE_FORCE_LOGIN alert."""
    test_ip = "192.168.10.2"
    for i in range(5):
        client.post(
            "/auth/login",
            json={"email": "user@authshield.io", "password": f"wrong{i}"},
            headers={"X-Simulated-IP": test_ip}
        )

    alerts_resp = client.get(
        "/alerts",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    alerts = alerts_resp.json()
    bf_alerts = [a for a in alerts if a["source_ip"] == test_ip and a["alert_type"] == "BRUTE_FORCE_LOGIN"]
    assert len(bf_alerts) == 1
    assert bf_alerts[0]["severity"] == "HIGH"
    assert bf_alerts[0]["status"] == "OPEN"


def test_repeated_unauthorized_access_triggers_alert(client, user_token, analyst_token):
    """3 unauthorized access attempts should trigger REPEATED_UNAUTHORIZED_ACCESS alert."""
    test_ip = "192.168.10.3"
    for _ in range(3):
        resp = client.get(
            "/users",
            headers={"Authorization": f"Bearer {user_token}", "X-Simulated-IP": test_ip}
        )
        assert resp.status_code == 403

    alerts_resp = client.get(
        "/alerts",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    unauth_alerts = [
        a for a in alerts_resp.json()
        if a["source_ip"] == test_ip and a["alert_type"] == "REPEATED_UNAUTHORIZED_ACCESS"
    ]
    assert len(unauth_alerts) == 1
    assert unauth_alerts[0]["severity"] == "MEDIUM"


def test_privilege_escalation_triggers_alert(client, admin_token, analyst_token):
    """Promoting a user to admin role should trigger a PRIVILEGE_CHANGE alert."""
    admin_ip = "192.168.10.4"
    promote_resp = client.patch(
        "/users/3/role",
        json={"role_name": "admin"},
        headers={"Authorization": f"Bearer {admin_token}", "X-Simulated-IP": admin_ip}
    )
    assert promote_resp.status_code == 200

    alerts_resp = client.get(
        "/alerts",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    priv_alerts = [
        a for a in alerts_resp.json()
        if a["alert_type"] == "PRIVILEGE_CHANGE" and a["user_id"] == 3
    ]
    assert len(priv_alerts) == 1
    assert priv_alerts[0]["severity"] == "HIGH"


def test_disabled_account_login_triggers_alert(client, analyst_token):
    """Attempting login with disabled user credentials triggers LOGIN_ATTEMPT_DISABLED_ACCOUNT."""
    sim_ip = "192.168.10.5"
    resp = client.post(
        "/auth/login",
        json={"email": "disabled@authshield.io", "password": "DisabledPassword123!"},
        headers={"X-Simulated-IP": sim_ip}
    )
    assert resp.status_code == 403

    alerts_resp = client.get(
        "/alerts",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    dis_alerts = [
        a for a in alerts_resp.json()
        if a["alert_type"] == "LOGIN_ATTEMPT_DISABLED_ACCOUNT" and a["source_ip"] == sim_ip
    ]
    assert len(dis_alerts) == 1
    assert dis_alerts[0]["severity"] == "HIGH"
