"""Tests for Active Defense, IP Blocklisting, and User Quarantine Remediation."""

import pytest
from fastapi import status
from app.services.blocklist_service import BlocklistService
from app.models.user import User


def test_manual_ip_block_and_unblock(db_session):
    """Test manual IP blocking and unblocking service lifecycle."""
    test_ip = "198.51.100.42"

    # Initially not blocked
    assert BlocklistService.is_ip_blocked(db_session, test_ip) is False

    # Block IP
    entry = BlocklistService.block_ip(
        db=db_session,
        ip_address=test_ip,
        reason="Observed port scan and brute force",
        blocked_by="analyst@authshield.io"
    )
    assert entry.is_active is True
    assert entry.ip_address == test_ip
    assert BlocklistService.is_ip_blocked(db_session, test_ip) is True

    # Unblock IP
    unblocked = BlocklistService.unblock_ip(db_session, test_ip, unblocked_by="admin@authshield.io")
    assert unblocked is True
    assert BlocklistService.is_ip_blocked(db_session, test_ip) is False


def test_ip_blocklist_middleware_enforcement(client, db_session):
    """Test that blocked IPs are actively rejected by the middleware with HTTP 403."""
    attacker_ip = "203.0.113.99"

    # Before block: request succeeds or returns 401 for bad login
    resp_before = client.post(
        "/auth/login",
        json={"email": "admin@authshield.io", "password": "WrongPassword!"},
        headers={"X-Simulated-IP": attacker_ip}
    )
    assert resp_before.status_code == status.HTTP_401_UNAUTHORIZED

    # Manually block attacker IP
    BlocklistService.block_ip(db_session, attacker_ip, reason="Automated attack pattern")

    # After block: request is actively rejected by middleware with 403 Forbidden
    resp_after = client.post(
        "/auth/login",
        json={"email": "admin@authshield.io", "password": "AdminPassword123!"},
        headers={"X-Simulated-IP": attacker_ip}
    )
    assert resp_after.status_code == status.HTTP_403_FORBIDDEN
    assert "quarantined by AuthShield security policy" in resp_after.json()["detail"]

    # Release IP
    BlocklistService.unblock_ip(db_session, attacker_ip)

    # After unblock: valid login succeeds
    resp_released = client.post(
        "/auth/login",
        json={"email": "admin@authshield.io", "password": "AdminPassword123!"},
        headers={"X-Simulated-IP": attacker_ip}
    )
    assert resp_released.status_code == status.HTTP_200_OK


def test_analyst_can_manage_remediation_endpoints(client, db_session):
    """Test remediation REST API endpoints with analyst token."""
    login_resp = client.post(
        "/auth/login",
        json={"email": "analyst@authshield.io", "password": "AnalystPassword123!"}
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    target_ip = "192.0.2.77"

    # 1. Block IP via API
    block_resp = client.post(
        "/remediation/block-ip",
        json={"ip_address": target_ip, "reason": "Suspicious authorization anomaly"},
        headers=headers
    )
    assert block_resp.status_code == status.HTTP_200_OK
    assert block_resp.json()["status"] == "success"

    # 2. List blocked IPs
    list_resp = client.get("/remediation/blocked-ips", headers=headers)
    assert list_resp.status_code == status.HTTP_200_OK
    blocked_ips = [item["ip_address"] for item in list_resp.json()]
    assert target_ip in blocked_ips

    # 3. Unblock IP via API
    unblock_resp = client.post(
        "/remediation/unblock-ip",
        json={"ip_address": target_ip},
        headers=headers
    )
    assert unblock_resp.status_code == status.HTTP_200_OK

    # 4. Quarantine user account
    user = db_session.query(User).filter(User.username == "user").first()
    quarantine_resp = client.post(f"/remediation/quarantine-user/{user.id}", headers=headers)
    assert quarantine_resp.status_code == status.HTTP_200_OK
    assert quarantine_resp.json()["new_status"] == "disabled"

    # 5. Restore user account
    restore_resp = client.post(f"/remediation/restore-user/{user.id}", headers=headers)
    assert restore_resp.status_code == status.HTTP_200_OK
    assert restore_resp.json()["new_status"] == "active"


def test_standard_user_denied_remediation_endpoints(client):
    """Test that standard users (role: user) cannot invoke remediation endpoints."""
    login_resp = client.post(
        "/auth/login",
        json={"email": "user@authshield.io", "password": "UserPassword123!"}
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/remediation/blocked-ips", headers=headers)
    assert resp.status_code == status.HTTP_403_FORBIDDEN
