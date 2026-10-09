"""Pydantic schemas for AI Threat Intelligence and SOC Copilot insights."""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class AIAttemptRecord(BaseModel):
    provider: str
    model: str
    status: str  # "SUCCESS", "FAILED", "SKIPPED"
    error: Optional[str] = None
    latency_ms: Optional[int] = None


class AIInsightResponse(BaseModel):
    success: bool = True
    provider: str
    model: str
    fallback_occurred: bool = False
    latency_ms: int = 0
    attempts: List[AIAttemptRecord] = []
    summary: str
    mitre_attack: Optional[Dict[str, str]] = None
    risk_level: Optional[str] = None
    immediate_actions: List[str] = []
    raw_content: str


class AISOCPostureResponse(BaseModel):
    success: bool = True
    provider: str
    model: str
    fallback_occurred: bool = False
    latency_ms: int = 0
    attempts: List[AIAttemptRecord] = []
    briefing: str
    threat_level: str
    key_findings: List[str] = []
    recommended_actions: List[str] = []
    raw_content: str


class AICopilotRequest(BaseModel):
    prompt: str = Field(..., min_length=2, max_length=2000, description="Analyst question or prompt")
    context_alert_id: Optional[int] = Field(None, description="Optional alert ID to inject as investigation context")


class AICopilotResponse(BaseModel):
    success: bool = True
    provider: str
    model: str
    fallback_occurred: bool = False
    latency_ms: int = 0
    attempts: List[AIAttemptRecord] = []
    response: str


class AIProviderStatus(BaseModel):
    provider: str
    configured: bool
    healthy: bool
    message: str
    primary_model: str
    latency_ms: Optional[int] = None
