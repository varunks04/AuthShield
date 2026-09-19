"""Pytest configuration and test fixtures for AuthShield."""

import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.connection import Base, get_db
from app.database.init_db import init_db

# Test database: in-memory SQLite shared connection pool
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session():
    """Create fresh database tables for each test function."""
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    init_db(session)
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session):
    """Provides a TestClient using the isolated in-memory test database."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def admin_token(client):
    """Helper fixture providing an authenticated Admin JWT token."""
    resp = client.post(
        "/auth/login",
        json={"email": "admin@authshield.io", "password": "AdminPassword123!"}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture
def analyst_token(client):
    """Helper fixture providing an authenticated Analyst JWT token."""
    resp = client.post(
        "/auth/login",
        json={"email": "analyst@authshield.io", "password": "AnalystPassword123!"}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture
def user_token(client):
    """Helper fixture providing an authenticated normal User JWT token."""
    resp = client.post(
        "/auth/login",
        json={"email": "user@authshield.io", "password": "UserPassword123!"}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]
