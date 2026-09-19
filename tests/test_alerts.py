"""Alert Management & Triage Workflow Tests (PRD Section 19)."""


def test_alert_detail_retrieval(client, analyst_token):
    """Verify detailed alert retrieval by alert ID."""
    # Trigger an alert via 5 failed logins
    for i in range(5):
        client.post(
            "/auth/login",
            json={"email": "user@authshield.io", "password": f"wrong{i}"},
            headers={"X-Simulated-IP": "10.50.0.1"}
        )

    alerts_resp = client.get(
        "/alerts",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    alerts = alerts_resp.json()
    assert len(alerts) >= 1
    alert_id = alerts[0]["id"]

    detail_resp = client.get(
        f"/alerts/{alert_id}",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert detail_resp.status_code == 200
    assert detail_resp.json()["id"] == alert_id


def test_alert_triage_status_lifecycle(client, analyst_token):
    """Verify alert status transitions: OPEN -> INVESTIGATING -> RESOLVED -> FALSE_POSITIVE."""
    # Trigger an alert
    for i in range(5):
        client.post(
            "/auth/login",
            json={"email": "user@authshield.io", "password": f"bad{i}"},
            headers={"X-Simulated-IP": "10.50.0.2"}
        )

    alerts_resp = client.get(
        "/alerts",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    alert = next(a for a in alerts_resp.json() if a["source_ip"] == "10.50.0.2")
    alert_id = alert["id"]
    assert alert["status"] == "OPEN"

    # Step 1: Transition to INVESTIGATING
    s1 = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": "INVESTIGATING"},
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert s1.status_code == 200
    assert s1.json()["status"] == "INVESTIGATING"

    # Step 2: Transition to RESOLVED
    s2 = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": "RESOLVED"},
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert s2.status_code == 200
    assert s2.json()["status"] == "RESOLVED"

    # Step 3: Transition to FALSE_POSITIVE
    s3 = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": "FALSE_POSITIVE"},
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert s3.status_code == 200
    assert s3.json()["status"] == "FALSE_POSITIVE"


def test_alert_summary_statistics(client, analyst_token):
    """Verify the /alerts/summary/stats endpoint returns correct summary structure."""
    stats_resp = client.get(
        "/alerts/summary/stats",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert stats_resp.status_code == 200
    data = stats_resp.json()
    assert "total" in data
    assert "open" in data
    assert "investigating" in data
    assert "resolved" in data
    assert "by_severity" in data
