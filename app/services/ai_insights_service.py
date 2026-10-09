"""AI Threat Intelligence & Multi-Model Fallback Orchestrator for AuthShield.

Orchestrates AI analysis across configured providers (Groq, OpenRouter) with
automatic failover chaining and an offline deterministic cybersecurity heuristic engine.
"""

import os
import time
import re
import logging
from typing import List, Dict, Any, Optional, Tuple
import httpx
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.config import settings
from app.models.alert import SecurityAlert
from app.models.audit import AuditLog
from app.models.user import User
from app.models.blocklist import BlockedIP
from app.schemas.insights import (
    AIAttemptRecord,
    AIInsightResponse,
    AISOCPostureResponse,
    AICopilotResponse,
    AIProviderStatus,
)

logger = logging.getLogger("authshield.ai_insights")
logger.setLevel(logging.INFO)


class AIInsightsService:
    """Multi-model AI Orchestration Service with automated fallback."""

    # Ordered list of remote model candidates for fallback orchestration
    CANDIDATES: List[Dict[str, str]] = [
        # Tier 1: Groq Ultra-fast inference (Primary)
        {"provider": "Groq", "model": "qwen/qwen3.8-27b", "endpoint": "https://api.groq.com/openai/v1/chat/completions"},
        # Tier 2: Groq Alternative Models
        {"provider": "Groq", "model": "openai/gpt-oss-120b", "endpoint": "https://api.groq.com/openai/v1/chat/completions"},
        {"provider": "Groq", "model": "openai/gpt-oss-20b", "endpoint": "https://api.groq.com/openai/v1/chat/completions"},
        # Tier 3: OpenRouter Free Models (Secondary Provider)
        {"provider": "OpenRouter", "model": "nvidia/nemotron-3.5-lightning:free", "endpoint": "https://openrouter.ai/api/v1/chat/completions"},
        {"provider": "OpenRouter", "model": "liquid/lfm-2.5-2.6b:free", "endpoint": "https://openrouter.ai/api/v1/chat/completions"},
        {"provider": "OpenRouter", "model": "google/gemma-4-31b-it:free", "endpoint": "https://openrouter.ai/api/v1/chat/completions"},
        {"provider": "OpenRouter", "model": "google/gemma-4-26b-a4b-it:free", "endpoint": "https://openrouter.ai/api/v1/chat/completions"},
    ]

    @classmethod
    def _get_api_key(cls, provider: str) -> Optional[str]:
        """Fetch API key from settings or environment for a given provider."""
        if provider == "Groq":
            return settings.GROQ_API_KEY or os.getenv("GROQ_API_KEY")
        elif provider == "OpenRouter":
            return settings.OPENROUTER_API_KEY or os.getenv("OPENROUTER_API_KEY")
        return None

    @classmethod
    def _execute_with_fallback(
        cls,
        messages: List[Dict[str, str]],
        max_tokens: int = 800,
        temperature: float = 0.2,
        timeout_seconds: float = 8.0,
    ) -> Tuple[str, str, str, bool, int, List[AIAttemptRecord]]:
        """
        Execute chat completion through ordered candidate models with fallback.
        
        Returns:
            (content, provider_used, model_used, fallback_occurred, latency_ms, attempts_history)
        """
        attempts: List[AIAttemptRecord] = []
        overall_start = time.time()
        fallback_occurred = False

        for index, candidate in enumerate(cls.CANDIDATES):
            provider = candidate["provider"]
            model = candidate["model"]
            endpoint = candidate["endpoint"]
            api_key = cls._get_api_key(provider)

            if not api_key:
                attempts.append(AIAttemptRecord(
                    provider=provider,
                    model=model,
                    status="SKIPPED",
                    error=f"No API key configured for {provider}"
                ))
                continue

            # If we are past the first attempted candidate, fallback has occurred
            if any(a.status in ("FAILED", "SUCCESS") for a in attempts):
                fallback_occurred = True

            req_start = time.time()
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }
            if provider == "OpenRouter":
                headers["HTTP-Referer"] = "https://authshield.io"
                headers["X-Title"] = "AuthShield SOC Threat Intelligence"

            payload = {
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }

            try:
                logger.info(f"AI Orchestrator: Attempting {provider} ({model})...")
                with httpx.Client(timeout=timeout_seconds) as client:
                    response = client.post(endpoint, headers=headers, json=payload)

                req_duration_ms = int((time.time() - req_start) * 1000)

                if response.status_code == 200:
                    data = response.json()
                    choices = data.get("choices", [])
                    if choices:
                        msg = choices[0].get("message", {})
                        content = msg.get("content") or ""
                        # Handle reasoning models where output might be in reasoning if content empty
                        if not content.strip() and msg.get("reasoning"):
                            content = msg.get("reasoning")

                        if content.strip():
                            attempts.append(AIAttemptRecord(
                                provider=provider,
                                model=model,
                                status="SUCCESS",
                                latency_ms=req_duration_ms
                            ))
                            logger.info(f"AI Orchestrator: Success on {provider} ({model}) in {req_duration_ms}ms")
                            return (
                                content.strip(),
                                provider,
                                model,
                                fallback_occurred,
                                req_duration_ms,
                                attempts,
                            )

                    # Empty content or malformed response
                    attempts.append(AIAttemptRecord(
                        provider=provider,
                        model=model,
                        status="FAILED",
                        error="Empty response content",
                        latency_ms=req_duration_ms
                    ))
                else:
                    error_detail = response.text[:200]
                    attempts.append(AIAttemptRecord(
                        provider=provider,
                        model=model,
                        status="FAILED",
                        error=f"HTTP {response.status_code}: {error_detail}",
                        latency_ms=req_duration_ms
                    ))
                    logger.warning(f"AI Candidate failed ({provider} {model}): HTTP {response.status_code}")

            except Exception as exc:
                req_duration_ms = int((time.time() - req_start) * 1000)
                attempts.append(AIAttemptRecord(
                    provider=provider,
                    model=model,
                    status="FAILED",
                    error=str(exc),
                    latency_ms=req_duration_ms
                ))
                logger.warning(f"AI Candidate exception ({provider} {model}): {exc}")

        # If all remote models failed or no keys were present, activate offline deterministic heuristic fallback
        logger.warning("AI Orchestrator: All remote candidates exhausted or unavailable. Activating Offline Deterministic Heuristic Engine.")
        fallback_occurred = True
        offline_start = time.time()
        offline_content = cls._offline_heuristic_fallback(messages)
        offline_latency = int((time.time() - offline_start) * 1000)
        attempts.append(AIAttemptRecord(
            provider="Deterministic SOC Engine",
            model="authshield-rule-heuristics-v1",
            status="SUCCESS",
            latency_ms=offline_latency
        ))

        return (
            offline_content,
            "Deterministic SOC Engine",
            "authshield-rule-heuristics-v1",
            True,
            offline_latency,
            attempts,
        )

    # -------------------------------------------------------------------------
    # Offline Deterministic SOC Heuristic Engine
    # -------------------------------------------------------------------------
    @classmethod
    def _offline_heuristic_fallback(cls, messages: List[Dict[str, str]]) -> str:
        """
        High-fidelity cybersecurity rule engine that operates offline with zero external API calls.
        Guarantees that the SOC Analyst always receives high-value structured insights.
        """
        user_msg = ""
        for m in messages:
            if m.get("role") == "user":
                user_msg += m.get("content", "") + " "

        user_msg_lower = user_msg.lower()

        if "brute_force" in user_msg_lower or "failed logins" in user_msg_lower or "password" in user_msg_lower:
            return (
                "### Incident Executive Summary\n"
                "Automated authentication brute-force attempt identified. Multiple sequential authentication failures "
                "surpassed detection threshold within the monitoring window.\n\n"
                "### Threat Attribution & MITRE ATT&CK\n"
                "- **Tactic:** Credential Access (TA0006)\n"
                "- **Technique:** Brute Force: Password Guessing (T1110.001)\n"
                "- **Severity:** HIGH (Risk Score: 85/100)\n\n"
                "### Root Cause Analysis\n"
                "An adversary or automated dictionary bot launched repeated credential attacks against the authentication endpoint. "
                "Because rate-limiting or IP fencing had not yet been finalized, the threshold tripped the alert engine.\n\n"
                "### Immediate Remediation Checklist\n"
                "1. **Active Defense IP Containment:** Immediately quarantine the offending source IP via AuthShield Active Defense.\n"
                "2. **Account Protection:** Check target account lock state and enforce password reset if compromised.\n"
                "3. **MFA Enforcement:** Verify that Multi-Factor Authentication (MFA) challenge is enabled for the impacted username.\n"
                "4. **Telemetry Audit:** Search audit logs for any successful login originating from this IP in the previous 24 hours."
            )
        elif "unauthorized" in user_msg_lower or "role" in user_msg_lower or "privilege" in user_msg_lower:
            return (
                "### Incident Executive Summary\n"
                "Privilege boundary anomaly detected. An authenticated identity attempted unauthorized access to restricted endpoints "
                "outside its assigned RBAC permissions.\n\n"
                "### Threat Attribution & MITRE ATT&CK\n"
                "- **Tactic:** Privilege Escalation / Defense Evasion (TA0004 / TA0005)\n"
                "- **Technique:** Exploitation for Privilege Escalation (T1068) / Valid Accounts (T1078)\n"
                "- **Severity:** MEDIUM-HIGH (Risk Score: 78/100)\n\n"
                "### Root Cause Analysis\n"
                "The identity possesses standard user privileges but submitted requests targeting elevated administrative routers. "
                "This typically indicates compromised session cookies, rogue user enumeration, or misconfigured client-side routing.\n\n"
                "### Immediate Remediation Checklist\n"
                "1. **Session Invalidation:** Revoke active JWT bearer tokens for the affected user.\n"
                "2. **Account Quarantine:** Place the user account into quarantined status pending internal review.\n"
                "3. **RBAC Audit:** Inspect role assignments for unauthorized role mutation.\n"
                "4. **API Endpoint Fencing:** Ensure server-side `require_roles` dependencies remain strictly enforced on all handlers."
            )
        else:
            return (
                "### SOC Threat Intelligence Assessment\n"
                "AuthShield threat engine evaluated live telemetry and event patterns. Behavioral thresholds and IAM anomaly indicators "
                "were correlated across authentication and authorization activity.\n\n"
                "### Threat Attribution & MITRE ATT&CK\n"
                "- **Tactic:** Initial Access & Credential Access (TA0001 / TA0006)\n"
                "- **Technique:** Compromised Authentication & Access Token Misuse\n"
                "- **Severity:** MEDIUM (Risk Score: 65/100)\n\n"
                "### Immediate Remediation Checklist\n"
                "1. **Audit Inspection:** Review recent audit logs for correlated anomalies across adjacent IP subnets.\n"
                "2. **Active Defense:** Quarantine repeat offender IPs exhibiting suspicious traffic.\n"
                "3. **Security Posture:** Verify threshold settings (BRUTE_FORCE_THRESHOLD, UNAUTHORIZED_ACCESS_THRESHOLD)."
            )

    # -------------------------------------------------------------------------
    # Parsing Helpers
    # -------------------------------------------------------------------------
    @classmethod
    def _parse_sections(cls, raw: str) -> Dict[str, Any]:
        """Parse structured fields from LLM or heuristic output."""
        # Summary
        summary = ""
        summary_match = re.search(r"(?:###?\s*(?:Incident\s*)?Executive Summary\s*\n+)(.*?)(?=\n###?|\Z)", raw, re.DOTALL | re.IGNORECASE)
        if summary_match:
            summary = summary_match.group(1).strip()
        else:
            lines = [l.strip() for l in raw.split("\n") if l.strip() and not l.strip().startswith("#")]
            summary = lines[0] if lines else "Analysis completed by AuthShield AI Orchestrator."

        # Risk level
        risk_level = "HIGH"
        if "CRITICAL" in raw.upper():
            risk_level = "CRITICAL"
        elif "HIGH" in raw.upper():
            risk_level = "HIGH"
        elif "MEDIUM" in raw.upper():
            risk_level = "MEDIUM"
        elif "LOW" in raw.upper():
            risk_level = "LOW"

        # MITRE ATT&CK
        tactic = "Credential Access (TA0006)"
        technique = "Brute Force (T1110)"
        tactic_match = re.search(r"\*\*Tactic:\*\*\s*([^\n\r]+)", raw, re.IGNORECASE)
        if tactic_match:
            tactic = tactic_match.group(1).strip()
        technique_match = re.search(r"\*\*Technique:\*\*\s*([^\n\r]+)", raw, re.IGNORECASE)
        if technique_match:
            technique = technique_match.group(1).strip()

        # Immediate actions
        actions = []
        action_match = re.search(r"(?:###?\s*(?:Immediate\s*)?Remediation\s*(?:Checklist|Steps|Actions)?\s*\n+)(.*?)(?=\n###?|\Z)", raw, re.DOTALL | re.IGNORECASE)
        if action_match:
            action_block = action_match.group(1).strip()
            for line in action_block.split("\n"):
                cleaned = re.sub(r"^[\d\.\-\*\s]+", "", line).strip()
                if cleaned:
                    actions.append(cleaned)

        if not actions:
            actions = [
                "Inspect related audit logs for the offending IP or user account.",
                "Quarantine source IP in AuthShield Active Defense console.",
                "Enforce credential rotation or MFA challenge for targeted account."
            ]

        return {
            "summary": summary,
            "risk_level": risk_level,
            "mitre_attack": {"tactic": tactic, "technique": technique},
            "immediate_actions": actions[:6],
        }

    # -------------------------------------------------------------------------
    # Core Public Methods
    # -------------------------------------------------------------------------
    @classmethod
    def analyze_alert(cls, db: Session, alert_id: int) -> AIInsightResponse:
        """
        Deep-dive AI analysis for a specific security alert with full context and fallback.
        """
        alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if not alert:
            raise ValueError(f"Security Alert #{alert_id} not found in database.")

        # Gather surrounding audit logs for the same IP or user
        recent_logs = (
            db.query(AuditLog)
            .filter(
                (AuditLog.ip_address == alert.source_ip) |
                ((AuditLog.user_id == alert.user_id) if alert.user_id else False)
            )
            .order_by(AuditLog.timestamp.desc())
            .limit(10)
            .all()
        )

        logs_context = "\n".join([
            f"- [{log.timestamp}] Action: {log.action} | Status: {log.status} | IP: {log.ip_address} | Details: {log.details or 'N/A'}"
            for log in recent_logs
        ]) or "No recent audit logs found for this entity."

        user_info = "Unauthenticated / Anonymous"
        if alert.user_id:
            user = db.query(User).filter(User.id == alert.user_id).first()
            if user:
                user_info = f"Username: '{user.username}', Email: '{user.email}', Status: {user.status}, Role: {user.role.name if user.role else 'None'}"

        prompt = (
            f"You are AuthShield's Senior SOC Threat Analyst and Incident Responder. "
            f"Analyze the following security alert and correlated telemetry, then output concise, structured incident insights.\n\n"
            f"ALERT DETAILS:\n"
            f"- Alert ID: #{alert.id}\n"
            f"- Timestamp: {alert.timestamp}\n"
            f"- Alert Type: {alert.alert_type}\n"
            f"- Severity: {alert.severity}\n"
            f"- Source IP: {alert.source_ip}\n"
            f"- Targeted Identity: {user_info}\n"
            f"- Trigger Description: {alert.description}\n"
            f"- Current Status: {alert.status}\n\n"
            f"CORRELATED AUDIT LOGS:\n{logs_context}\n\n"
            f"FORMAT YOUR RESPONSE EXACTLY AS FOLLOWS:\n"
            f"### Incident Executive Summary\n"
            f"[2-3 sentence executive threat summary]\n\n"
            f"### Threat Attribution & MITRE ATT&CK\n"
            f"- **Tactic:** [e.g. Credential Access (TA0006)]\n"
            f"- **Technique:** [e.g. Brute Force (T1110.001)]\n"
            f"- **Severity:** [CRITICAL / HIGH / MEDIUM / LOW]\n\n"
            f"### Root Cause Analysis\n"
            f"[Concise explanation of how and why this trigger occurred]\n\n"
            f"### Immediate Remediation Checklist\n"
            f"1. [Action 1: Containment]\n"
            f"2. [Action 2: Eradication / Identity protection]\n"
            f"3. [Action 3: Active Defense / IP blocklist rule]\n"
            f"4. [Action 4: Hardening]"
        )

        messages = [
            {"role": "system", "content": "You are AuthShield's specialized IAM cybersecurity copilot. Be concise, authoritative, and actionable."},
            {"role": "user", "content": prompt}
        ]

        raw, provider, model, fallback, latency, attempts = cls._execute_with_fallback(
            messages=messages,
            max_tokens=750,
            temperature=0.1
        )

        parsed = cls._parse_sections(raw)

        return AIInsightResponse(
            success=True,
            provider=provider,
            model=model,
            fallback_occurred=fallback,
            latency_ms=latency,
            attempts=attempts,
            summary=parsed["summary"],
            mitre_attack=parsed["mitre_attack"],
            risk_level=parsed["risk_level"],
            immediate_actions=parsed["immediate_actions"],
            raw_content=raw,
        )

    @classmethod
    def analyze_soc_posture(cls, db: Session) -> AISOCPostureResponse:
        """
        Synthesize enterprise SOC threat briefing across fleet telemetry.
        """
        # Collect telemetry numbers
        total_alerts = db.query(func.count(SecurityAlert.id)).scalar() or 0
        open_alerts = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.status == "OPEN").scalar() or 0
        investigating = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.status == "INVESTIGATING").scalar() or 0
        blocked_ips_count = db.query(func.count(BlockedIP.id)).filter(BlockedIP.is_active.is_(True)).scalar() or 0
        quarantined_users = db.query(func.count(User.id)).filter(User.status == "disabled").scalar() or 0

        # Top offending IPs
        top_ips = (
            db.query(SecurityAlert.source_ip, func.count(SecurityAlert.id).label("count"))
            .group_by(SecurityAlert.source_ip)
            .order_by(func.count(SecurityAlert.id).desc())
            .limit(5)
            .all()
        )
        ip_summary = ", ".join([f"{ip} ({cnt} alerts)" for ip, cnt in top_ips]) or "None"

        prompt = (
            f"You are the CISO & SOC Lead AI Advisor for AuthShield. "
            f"Evaluate the current fleet security posture based on these live metrics:\n\n"
            f"- Total Recorded Alerts: {total_alerts}\n"
            f"- Active Unresolved Alerts (OPEN): {open_alerts}\n"
            f"- Alerts in Triage (INVESTIGATING): {investigating}\n"
            f"- Active Quarantined IPs: {blocked_ips_count}\n"
            f"- Suspended / Quarantined User Accounts: {quarantined_users}\n"
            f"- Top Alert Source IPs: {ip_summary}\n\n"
            f"PROVIDE A HIGH-LEVEL THREAT POSTURE BRIEFING WITH:\n"
            f"### Executive Posture Briefing\n"
            f"[2-3 sentence executive assessment of enterprise identity security]\n\n"
            f"### Fleet Threat Level\n"
            f"ELEVATED / HIGH / NOMINAL / CRITICAL\n\n"
            f"### Key Findings\n"
            f"1. [Finding 1]\n"
            f"2. [Finding 2]\n"
            f"3. [Finding 3]\n\n"
            f"### Recommended Strategic Actions\n"
            f"1. [Action 1]\n"
            f"2. [Action 2]\n"
            f"3. [Action 3]"
        )

        messages = [
            {"role": "system", "content": "You are AuthShield's Senior CISO threat advisor. Provide precise, actionable cyber defense analysis."},
            {"role": "user", "content": prompt}
        ]

        raw, provider, model, fallback, latency, attempts = cls._execute_with_fallback(
            messages=messages,
            max_tokens=650,
            temperature=0.2
        )

        # Parse posture sections
        threat_level = "ELEVATED" if open_alerts > 0 else "NOMINAL"
        if "CRITICAL" in raw.upper():
            threat_level = "CRITICAL"
        elif "HIGH" in raw.upper():
            threat_level = "HIGH"

        briefing = raw
        briefing_match = re.search(r"(?:###?\s*Executive Posture Briefing\s*\n+)(.*?)(?=\n###?|\Z)", raw, re.DOTALL | re.IGNORECASE)
        if briefing_match:
            briefing = briefing_match.group(1).strip()

        key_findings = []
        findings_match = re.search(r"(?:###?\s*Key Findings\s*\n+)(.*?)(?=\n###?|\Z)", raw, re.DOTALL | re.IGNORECASE)
        if findings_match:
            for l in findings_match.group(1).strip().split("\n"):
                c = re.sub(r"^[\d\.\-\*\s]+", "", l).strip()
                if c:
                    key_findings.append(c)

        rec_actions = []
        rec_match = re.search(r"(?:###?\s*Recommended Strategic Actions\s*\n+)(.*?)(?=\n###?|\Z)", raw, re.DOTALL | re.IGNORECASE)
        if rec_match:
            for l in rec_match.group(1).strip().split("\n"):
                c = re.sub(r"^[\d\.\-\*\s]+", "", l).strip()
                if c:
                    rec_actions.append(c)

        if not key_findings:
            key_findings = [f"{open_alerts} open alerts require analyst triage", f"{blocked_ips_count} offending IPs actively isolated"]
        if not rec_actions:
            rec_actions = ["Review open triage queue in Security Alerts console", "Audit Active Defense IP blocklist"]

        return AISOCPostureResponse(
            success=True,
            provider=provider,
            model=model,
            fallback_occurred=fallback,
            latency_ms=latency,
            attempts=attempts,
            briefing=briefing,
            threat_level=threat_level,
            key_findings=key_findings[:5],
            recommended_actions=rec_actions[:5],
            raw_content=raw,
        )

    @classmethod
    def ask_copilot(
        cls,
        db: Session,
        prompt: str,
        context_alert_id: Optional[int] = None
    ) -> AICopilotResponse:
        """
        Interactive SOC Copilot for ad-hoc threat inquiries and remediation guidance.
        """
        context_note = ""
        if context_alert_id:
            alert = db.query(SecurityAlert).filter(SecurityAlert.id == context_alert_id).first()
            if alert:
                context_note = (
                    f"\n[ACTIVE INVESTIGATION CONTEXT - Alert #{alert.id}]: "
                    f"Type={alert.alert_type}, Severity={alert.severity}, Source IP={alert.source_ip}, "
                    f"Description='{alert.description}', Status={alert.status}\n"
                )

        sys_msg = (
            "You are the AuthShield SOC Cyber Copilot. You assist Tier 1/Tier 2 security analysts "
            "with incident triage, threat attribution, IAM policy hardening, Active Defense containment commands, "
            "and MITRE ATT&CK framework correlation. Keep answers concise, technical, and actionable."
        )

        messages = [
            {"role": "system", "content": sys_msg},
            {"role": "user", "content": f"{context_note}{prompt}"}
        ]

        raw, provider, model, fallback, latency, attempts = cls._execute_with_fallback(
            messages=messages,
            max_tokens=600,
            temperature=0.2
        )

        return AICopilotResponse(
            success=True,
            provider=provider,
            model=model,
            fallback_occurred=fallback,
            latency_ms=latency,
            attempts=attempts,
            response=raw,
        )

    @classmethod
    def test_providers(cls) -> List[AIProviderStatus]:
        """
        Run health check and latency ping across configured AI providers.
        """
        results: List[AIProviderStatus] = []

        # 1. Test Groq
        groq_key = cls._get_api_key("Groq")
        if not groq_key:
            results.append(AIProviderStatus(
                provider="Groq",
                configured=False,
                healthy=False,
                message="GROQ_API_KEY not configured",
                primary_model="qwen/qwen3.8-27b"
            ))
        else:
            try:
                t0 = time.time()
                with httpx.Client(timeout=5.0) as client:
                    r = client.post(
                        "https://api.groq.com/openai/v1/chat/completions",
                        headers={"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"},
                        json={"model": "qwen/qwen3.8-27b", "messages": [{"role": "user", "content": "ping"}], "max_tokens": 5}
                    )
                ms = int((time.time() - t0) * 1000)
                if r.status_code == 200:
                    results.append(AIProviderStatus(
                        provider="Groq",
                        configured=True,
                        healthy=True,
                        message=f"Operational (HTTP 200)",
                        primary_model="qwen/qwen3.8-27b",
                        latency_ms=ms
                    ))
                else:
                    results.append(AIProviderStatus(
                        provider="Groq",
                        configured=True,
                        healthy=False,
                        message=f"HTTP {r.status_code}: {r.text[:100]}",
                        primary_model="qwen/qwen3.8-27b",
                        latency_ms=ms
                    ))
            except Exception as e:
                results.append(AIProviderStatus(
                    provider="Groq",
                    configured=True,
                    healthy=False,
                    message=f"Error: {str(e)}",
                    primary_model="qwen/qwen3.8-27b"
                ))

        # 2. Test OpenRouter
        or_key = cls._get_api_key("OpenRouter")
        if not or_key:
            results.append(AIProviderStatus(
                provider="OpenRouter",
                configured=False,
                healthy=False,
                message="OPENROUTER_API_KEY not configured",
                primary_model="nvidia/nemotron-3.5-lightning:free"
            ))
        else:
            try:
                t0 = time.time()
                with httpx.Client(timeout=5.0) as client:
                    r = client.post(
                        "https://openrouter.ai/api/v1/chat/completions",
                        headers={"Authorization": f"Bearer {or_key}", "Content-Type": "application/json", "HTTP-Referer": "https://authshield.io"},
                        json={"model": "nvidia/nemotron-3.5-lightning:free", "messages": [{"role": "user", "content": "ping"}], "max_tokens": 5}
                    )
                ms = int((time.time() - t0) * 1000)
                if r.status_code == 200:
                    results.append(AIProviderStatus(
                        provider="OpenRouter",
                        configured=True,
                        healthy=True,
                        message="Operational (HTTP 200)",
                        primary_model="nvidia/nemotron-3.5-lightning:free",
                        latency_ms=ms
                    ))
                else:
                    results.append(AIProviderStatus(
                        provider="OpenRouter",
                        configured=True,
                        healthy=False,
                        message=f"HTTP {r.status_code}: {r.text[:100]}",
                        primary_model="nvidia/nemotron-3.5-lightning:free",
                        latency_ms=ms
                    ))
            except Exception as e:
                results.append(AIProviderStatus(
                    provider="OpenRouter",
                    configured=True,
                    healthy=False,
                    message=f"Error: {str(e)}",
                    primary_model="nvidia/nemotron-3.5-lightning:free"
                ))

        # 3. Deterministic Fallback Engine (always healthy)
        results.append(AIProviderStatus(
            provider="Deterministic SOC Engine",
            configured=True,
            healthy=True,
            message="Offline Cybersecurity Heuristic Engine Ready",
            primary_model="authshield-rule-heuristics-v1",
            latency_ms=1
        ))

        return results
