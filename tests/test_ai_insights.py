"""Unit & Integration tests for AI Threat Intelligence & Fallback Orchestration."""

from unittest.mock import patch
from app.services.ai_insights_service import AIInsightsService
from app.config import settings


def test_ai_providers_status_endpoint(client, analyst_token):
    """Verify /insights/providers returns status for all orchestrated tiers."""
    resp = client.get(
        "/insights/providers",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert resp.status_code == 200
    providers = resp.json()
    assert len(providers) >= 3
    provider_names = [p["provider"] for p in providers]
    assert "Groq" in provider_names
    assert "OpenRouter" in provider_names
    assert "Deterministic SOC Engine" in provider_names


def test_ai_providers_unauthorized_access(client, user_token):
    """Verify regular users cannot access AI threat intelligence endpoints."""
    resp = client.get(
        "/insights/providers",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert resp.status_code == 403


def test_offline_heuristic_fallback():
    """Verify deterministic cybersecurity heuristic engine functions reliably with zero API calls."""
    messages = [
        {"role": "user", "content": "Alert #1: BRUTE_FORCE detected from IP 192.168.1.100 on user admin"}
    ]
    result = AIInsightsService._offline_heuristic_fallback(messages)
    assert "Executive Summary" in result
    assert "MITRE ATT&CK" in result
    assert "Immediate Remediation" in result
    assert "TA0006" in result or "T1110" in result


def test_fallback_cascade_on_simulated_failures():
    """Simulate remote API failures to verify fallback chain reaches deterministic engine."""
    with patch.object(AIInsightsService, "_get_api_key", return_value="invalid_dummy_key"):
        content, provider, model, fallback, latency, attempts = AIInsightsService._execute_with_fallback(
            messages=[{"role": "user", "content": "Analyze brute_force attempt"}]
        )
        assert fallback is True
        assert provider == "Deterministic SOC Engine"
        assert model == "authshield-rule-heuristics-v1"
        assert len(attempts) >= 1
        assert "Executive Summary" in content


def test_alert_ai_insights_endpoint(client, analyst_token):
    """Trigger an alert, then call /insights/alert/{id} and verify structured response."""
    # Trigger an alert via 5 failed logins
    for i in range(5):
        client.post(
            "/auth/login",
            json={"email": "user@authshield.io", "password": f"wrong_{i}"},
            headers={"X-Simulated-IP": "172.16.0.42"}
        )

    alerts_resp = client.get(
        "/alerts",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    alert = next(a for a in alerts_resp.json() if a["source_ip"] == "172.16.0.42")
    alert_id = alert["id"]

    resp = client.post(
        f"/insights/alert/{alert_id}",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert "provider" in data
    assert "model" in data
    assert "summary" in data
    assert "immediate_actions" in data
    assert len(data["immediate_actions"]) >= 1


def test_soc_posture_insights_endpoint(client, analyst_token):
    """Verify /insights/soc-posture returns executive briefing and posture metrics."""
    resp = client.post(
        "/insights/soc-posture",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert "threat_level" in data
    assert "briefing" in data
    assert "key_findings" in data
    assert "recommended_actions" in data


def test_soc_copilot_endpoint(client, analyst_token):
    """Verify /insights/copilot answers threat inquiries."""
    resp = client.post(
        "/insights/copilot",
        json={"prompt": "How do I mitigate credential stuffing on auth routes?"},
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert "response" in data
    assert len(data["response"]) > 20
