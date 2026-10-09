"""AI Threat Intelligence & SOC Copilot API Endpoints."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.user import User
from app.auth.permissions import require_roles
from app.services.ai_insights_service import AIInsightsService
from app.schemas.insights import (
    AIInsightResponse,
    AISOCPostureResponse,
    AICopilotRequest,
    AICopilotResponse,
    AIProviderStatus,
)

router = APIRouter(prefix="/insights", tags=["AI Threat Intelligence & Copilot"])


@router.get("/providers", response_model=List[AIProviderStatus])
def get_ai_providers_status(
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    """
    Check connection status, health, and latency of orchestrated AI model providers.
    """
    return AIInsightsService.test_providers()


@router.post("/alert/{alert_id}", response_model=AIInsightResponse)
def get_alert_ai_insights(
    alert_id: int,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """
    Generate automated AI security investigation, MITRE ATT&CK mapping,
    and remediation actions for a specific alert with multi-model fallback.
    """
    try:
        return AIInsightsService.analyze_alert(db=db, alert_id=alert_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI orchestration failed: {str(e)}",
        )


@router.post("/soc-posture", response_model=AISOCPostureResponse)
def get_soc_posture_insights(
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """
    Synthesize enterprise CISO and SOC threat briefing across fleet telemetry with multi-model fallback.
    """
    try:
        return AIInsightsService.analyze_soc_posture(db=db)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI orchestration failed: {str(e)}",
        )


@router.post("/copilot", response_model=AICopilotResponse)
def query_soc_copilot(
    payload: AICopilotRequest,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """
    Interactive SOC Cyber Copilot for ad-hoc threat inquiries and remediation guidance.
    """
    try:
        return AIInsightsService.ask_copilot(
            db=db,
            prompt=payload.prompt,
            context_alert_id=payload.context_alert_id,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI copilot query failed: {str(e)}",
        )
