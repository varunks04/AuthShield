"""Authentication & Token Validation Tests (PRD Section 25)."""

import time
from datetime import timedelta
from app.auth.jwt import create_access_token


def test_valid_registration(client):
    """Verify standard user registration with default 'user' role."""
    resp = client.post(
        "/auth/register",
        json={
            "username": "newuser",
            "email": "newuser@authshield.io",
            "password": "SecurePassword123!"
        }
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["username"] == "newuser"
    assert data["email"] == "newuser@authshield.io"
    assert data["role"]["name"] == "user"
    assert "password" not in data
    assert "password_hash" not in data


def test_duplicate_email_registration_fails(client):
    """Verify duplicate email rejection."""
    resp = client.post(
        "/auth/register",
        json={
            "username": "another_user",
            "email": "user@authshield.io",
            "password": "SomePassword123!"
        }
    )
    assert resp.status_code == 400
    assert "email address already exists" in resp.json()["detail"]


def test_duplicate_username_registration_fails(client):
    """Verify duplicate username rejection."""
    resp = client.post(
        "/auth/register",
        json={
            "username": "user",
            "email": "different_email@authshield.io",
            "password": "SomePassword123!"
        }
    )
    assert resp.status_code == 400
    assert "username already exists" in resp.json()["detail"]


def test_valid_login(client):
    """Verify successful login returns valid JWT token."""
    resp = client.post(
        "/auth/login",
        json={"email": "user@authshield.io", "password": "UserPassword123!"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == "user"
    assert data["username"] == "user"


def test_invalid_password_login_fails(client):
    """Verify invalid password rejection."""
    resp = client.post(
        "/auth/login",
        json={"email": "user@authshield.io", "password": "IncorrectPassword"}
    )
    assert resp.status_code == 401
    assert "Invalid email or password" in resp.json()["detail"]


def test_nonexistent_user_login_fails(client):
    """Verify unknown user login rejection."""
    resp = client.post(
        "/auth/login",
        json={"email": "ghost@authshield.io", "password": "AnyPassword123!"}
    )
    assert resp.status_code == 401
    assert "Invalid email or password" in resp.json()["detail"]


def test_disabled_account_login_rejected(client):
    """Verify disabled account cannot login."""
    resp = client.post(
        "/auth/login",
        json={"email": "disabled@authshield.io", "password": "DisabledPassword123!"}
    )
    assert resp.status_code == 403
    assert "disabled" in resp.json()["detail"].lower()


def test_missing_jwt_token(client):
    """Verify protected endpoint rejects request with missing token."""
    resp = client.get("/users/me")
    assert resp.status_code == 401


def test_malformed_jwt_token(client):
    """Verify protected endpoint rejects malformed token."""
    resp = client.get(
        "/users/me",
        headers={"Authorization": "Bearer not.a.valid.jwt"}
    )
    assert resp.status_code == 401


def test_expired_jwt_token(client):
    """Verify expired token rejection."""
    expired_token = create_access_token(
        data={"sub": "1", "role": "admin"},
        expires_delta=timedelta(seconds=-10)
    )
    resp = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {expired_token}"}
    )
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower()
