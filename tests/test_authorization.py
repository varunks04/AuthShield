"""Authorization & Role-Based Access Control (RBAC) Tests (PRD Section 25)."""


def test_user_can_access_own_profile(client, user_token):
    """User can view own profile."""
    resp = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert resp.status_code == 200
    assert resp.json()["username"] == "user"


def test_user_can_update_own_profile(client, user_token):
    """User can update permitted profile fields."""
    resp = client.put(
        "/users/me",
        json={"username": "user_updated"},
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert resp.status_code == 200
    assert resp.json()["username"] == "user_updated"


def test_user_denied_access_to_admin_users_list(client, user_token):
    """User is denied access to admin/analyst users endpoint."""
    resp = client.get(
        "/users",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert resp.status_code == 403
    assert "access denied" in resp.json()["detail"].lower()


def test_user_denied_access_to_alerts(client, user_token):
    """Normal user cannot view security alerts."""
    resp = client.get(
        "/alerts",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert resp.status_code == 403


def test_analyst_can_access_alerts_and_audit_logs(client, analyst_token):
    """Analyst role can access alerts and audit logs."""
    alerts_resp = client.get(
        "/alerts",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert alerts_resp.status_code == 200

    audit_resp = client.get(
        "/audit-logs",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert audit_resp.status_code == 200


def test_analyst_cannot_modify_user_role(client, analyst_token):
    """Analyst role cannot perform administrative role changes."""
    resp = client.patch(
        "/users/3/role",
        json={"role_name": "admin"},
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert resp.status_code == 403


def test_admin_can_modify_user_role_and_status(client, admin_token):
    """Admin role can change user roles and enable/disable accounts."""
    # Modify role
    role_resp = client.patch(
        "/users/3/role",
        json={"role_name": "analyst"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert role_resp.status_code == 200
    assert role_resp.json()["role"]["name"] == "analyst"

    # Modify status
    status_resp = client.patch(
        "/users/3/status",
        json={"status": "disabled"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "disabled"
