"""Service for managing manually blocked IPs and threat containment."""

from typing import Optional, List
from sqlalchemy.orm import Session
from app.models.blocklist import BlockedIP
from app.services.audit_service import AuditService


class BlocklistService:
    @staticmethod
    def block_ip(
        db: Session,
        ip_address: str,
        reason: Optional[str] = "Manually blocked by security analyst",
        blocked_by: str = "analyst@authshield.io"
    ) -> BlockedIP:
        """Manually blocks an IP address, enforcing immediate containment."""
        clean_ip = ip_address.strip()
        entry = db.query(BlockedIP).filter(BlockedIP.ip_address == clean_ip).first()
        if entry:
            entry.is_active = True
            entry.reason = reason
            entry.blocked_by = blocked_by
        else:
            entry = BlockedIP(
                ip_address=clean_ip,
                reason=reason,
                blocked_by=blocked_by,
                is_active=True
            )
            db.add(entry)
        db.commit()
        db.refresh(entry)

        AuditService.log_event(
            db=db,
            action="IP_MANUALLY_BLOCKED",
            endpoint="/remediation/block-ip",
            status="SUCCESS",
            ip_address=clean_ip,
            details=f"IP '{clean_ip}' manually quarantined by {blocked_by}. Reason: {reason}"
        )
        return entry

    @staticmethod
    def unblock_ip(
        db: Session,
        ip_address: str,
        unblocked_by: str = "analyst@authshield.io"
    ) -> bool:
        """Releases an IP address from the active denylist."""
        clean_ip = ip_address.strip()
        entry = db.query(BlockedIP).filter(BlockedIP.ip_address == clean_ip).first()
        if entry and entry.is_active:
            entry.is_active = False
            db.commit()
            AuditService.log_event(
                db=db,
                action="IP_UNBLOCKED",
                endpoint="/remediation/unblock-ip",
                status="SUCCESS",
                ip_address=clean_ip,
                details=f"IP '{clean_ip}' released from blocklist by {unblocked_by}"
            )
            return True
        return False

    @staticmethod
    def is_ip_blocked(db: Session, ip_address: str) -> bool:
        """Verifies if an IP address is actively quarantined."""
        clean_ip = ip_address.strip()
        return db.query(BlockedIP).filter(
            BlockedIP.ip_address == clean_ip,
            BlockedIP.is_active == True
        ).first() is not None

    @staticmethod
    def get_all_blocked(db: Session) -> List[BlockedIP]:
        """Returns all actively blocked IP addresses."""
        return db.query(BlockedIP).filter(
            BlockedIP.is_active == True
        ).order_by(BlockedIP.timestamp.desc()).all()
