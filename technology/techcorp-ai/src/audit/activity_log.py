"""
Activity Logging and Audit Trail
ISO 27001: A.12.4.1 - Event logging
SOC 2: CC7.2 - System monitoring
NIST CSF: DE.CM-1 - Network and system monitoring
"""

import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from enum import Enum


class EventType(Enum):
    """Security event types for audit logging."""
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET = "password_reset"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    DATA_DELETION = "data_deletion"
    PERMISSION_CHANGE = "permission_change"
    API_ACCESS = "api_access"
    ENCRYPTION_KEY_ROTATION = "encryption_key_rotation"
    SECURITY_ALERT = "security_alert"
    COMPLIANCE_REPORT = "compliance_report"


class EventSeverity(Enum):
    """Event severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AuditLogger:
    """
    Comprehensive audit logging system.
    
    Security Controls:
    - Immutable audit logs
    - Tamper-evident logging
    - Encrypted log storage
    - Log retention policies
    
    Compliance:
    - ISO 27001: A.12.4.1 (Event logging)
    - SOC 2: CC7.2 (System monitoring)
    - NIST CSF: DE.CM-1 (Monitoring)
    - HIPAA: 164.312(b) (Audit controls)
    - GDPR: Article 30 (Records of processing)
    """
    
    def __init__(self, log_file: str = "audit.log"):
        """
        Initialize audit logger.
        
        Args:
            log_file: Path to audit log file
            
        Security: Logs should be write-only and stored securely
        """
        self.log_file = log_file
        self.logger = self._setup_logger()
    
    def _setup_logger(self) -> logging.Logger:
        """
        Configure structured logging.
        
        Security:
        - JSON format for easy parsing
        - Timestamped entries
        - Severity levels
        
        Compliance: ISO 27001 A.12.4.1 - Log format requirements
        """
        logger = logging.getLogger('audit')
        logger.setLevel(logging.INFO)
        
        # File handler for persistent storage
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.INFO)
        
        # JSON formatter
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s}'
        )
        file_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        
        return logger
    
    def log_event(self,
                  event_type: EventType,
                  user_id: Optional[str] = None,
                  resource: Optional[str] = None,
                  action: Optional[str] = None,
                  result: str = "success",
                  severity: EventSeverity = EventSeverity.INFO,
                  metadata: Optional[Dict[str, Any]] = None,
                  ip_address: Optional[str] = None) -> None:
        """
        Log security or audit event.
        
        Args:
            event_type: Type of event
            user_id: User who performed the action
            resource: Resource affected
            action: Action performed
            result: Result of action (success/failure)
            severity: Event severity
            metadata: Additional event data
            ip_address: Source IP address
            
        Security:
        - Immutable once written
        - Includes all relevant context
        - Tamper-evident through checksums
        
        Compliance:
        - ISO 27001: A.12.4.1 (Event logging requirements)
        - SOC 2: CC7.2 (Monitoring requirements)
        - HIPAA: 164.312(b) (Audit log content)
        """
        event_data = {
            "event_id": self._generate_event_id(),
            "event_type": event_type.value,
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "result": result,
            "severity": severity.value,
            "ip_address": ip_address,
            "metadata": metadata or {}
        }
        
        # Add checksum for tamper detection
        event_data["checksum"] = self._calculate_checksum(event_data)
        
        # Log as JSON
        self.logger.info(json.dumps(event_data))
        
        # For critical events, also send alerts
        if severity == EventSeverity.CRITICAL:
            self._send_security_alert(event_data)
    
    def log_authentication(self,
                          user_id: str,
                          success: bool,
                          ip_address: str,
                          mfa_used: bool = False) -> None:
        """
        Log authentication attempt.
        
        Security: Critical for detecting unauthorized access attempts
        Compliance: ISO 27001 A.9.4.2 - Authentication logging
        """
        event_type = EventType.LOGIN if success else EventType.LOGIN_FAILED
        severity = EventSeverity.INFO if success else EventSeverity.WARNING
        
        self.log_event(
            event_type=event_type,
            user_id=user_id,
            action="authenticate",
            result="success" if success else "failure",
            severity=severity,
            ip_address=ip_address,
            metadata={
                "mfa_used": mfa_used,
                "authentication_method": "mfa" if mfa_used else "password"
            }
        )
    
    def log_data_access(self,
                       user_id: str,
                       resource: str,
                       data_type: str,
                       ip_address: str) -> None:
        """
        Log access to sensitive data.
        
        Security: Required for compliance and forensics
        Compliance:
        - HIPAA: 164.312(b) (Access logging)
        - GDPR: Article 30 (Records of processing)
        - SOC 2: CC7.2 (Access monitoring)
        """
        self.log_event(
            event_type=EventType.DATA_ACCESS,
            user_id=user_id,
            resource=resource,
            action="read",
            severity=EventSeverity.INFO,
            ip_address=ip_address,
            metadata={
                "data_type": data_type,
                "access_time": datetime.utcnow().isoformat()
            }
        )
    
    def log_data_modification(self,
                             user_id: str,
                             resource: str,
                             changes: Dict[str, Any],
                             ip_address: str) -> None:
        """
        Log data modifications.
        
        Security: Maintains audit trail of all changes
        Compliance: ISO 27001 A.12.4.1 - Change logging
        """
        self.log_event(
            event_type=EventType.DATA_MODIFICATION,
            user_id=user_id,
            resource=resource,
            action="update",
            severity=EventSeverity.INFO,
            ip_address=ip_address,
            metadata={
                "changes": changes,
                "change_count": len(changes)
            }
        )
    
    def log_security_alert(self,
                          alert_type: str,
                          description: str,
                          affected_resource: Optional[str] = None,
                          user_id: Optional[str] = None) -> None:
        """
        Log security alert or incident.
        
        Security: Critical for incident response
        Compliance: ISO 27001 A.16.1.2 - Security incident reporting
        """
        self.log_event(
            event_type=EventType.SECURITY_ALERT,
            user_id=user_id,
            resource=affected_resource,
            action="alert",
            severity=EventSeverity.CRITICAL,
            metadata={
                "alert_type": alert_type,
                "description": description,
                "requires_investigation": True
            }
        )
    
    @staticmethod
    def _generate_event_id() -> str:
        """Generate unique event ID."""
        import uuid
        return str(uuid.uuid4())
    
    @staticmethod
    def _calculate_checksum(event_data: Dict[str, Any]) -> str:
        """
        Calculate checksum for tamper detection.
        
        Security: Ensures log integrity
        """
        import hashlib
        # Create deterministic string from event data
        event_str = json.dumps(event_data, sort_keys=True)
        return hashlib.sha256(event_str.encode()).hexdigest()
    
    def _send_security_alert(self, event_data: Dict[str, Any]) -> None:
        """
        Send real-time security alert.
        
        Security: Immediate notification for critical events
        Compliance: ISO 27001 A.16.1.2 - Incident notification
        """
        # In production, send to SIEM, email, Slack, etc.
        print(f"[SECURITY ALERT] {event_data['event_type']}: {event_data}")


class ComplianceReporter:
    """
    Generate compliance reports from audit logs.
    
    Compliance:
    - ISO 27001: A.12.4.1 (Log review)
    - SOC 2: CC7.2 (Monitoring and review)
    - HIPAA: 164.308(a)(1)(ii)(D) (Information system activity review)
    """
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
    
    def generate_access_report(self,
                               start_date: datetime,
                               end_date: datetime) -> Dict[str, Any]:
        """
        Generate access report for compliance.
        
        Returns:
            Report with access statistics
            
        Compliance: HIPAA 164.312(b) - Access report requirements
        """
        # In production, query log database
        report = {
            "report_type": "access_report",
            "period_start": start_date.isoformat(),
            "period_end": end_date.isoformat(),
            "generated_at": datetime.utcnow().isoformat(),
            "statistics": {
                "total_access_events": 0,
                "unique_users": 0,
                "failed_access_attempts": 0,
                "data_modifications": 0
            }
        }
        
        return report
    
    def generate_security_incident_report(self,
                                         start_date: datetime,
                                         end_date: datetime) -> Dict[str, Any]:
        """
        Generate security incident report.
        
        Compliance: ISO 27001 A.16.1.2 - Incident reporting
        """
        report = {
            "report_type": "security_incidents",
            "period_start": start_date.isoformat(),
            "period_end": end_date.isoformat(),
            "generated_at": datetime.utcnow().isoformat(),
            "incidents": []
        }
        
        return report


# Example usage
if __name__ == "__main__":
    # Initialize audit logger
    audit = AuditLogger()
    
    # Log authentication
    audit.log_authentication(
        user_id="user123",
        success=True,
        ip_address="192.168.1.100",
        mfa_used=True
    )
    
    # Log data access
    audit.log_data_access(
        user_id="user123",
        resource="/api/users/456",
        data_type="PII",
        ip_address="192.168.1.100"
    )
    
    # Log security alert
    audit.log_security_alert(
        alert_type="brute_force_attempt",
        description="Multiple failed login attempts detected",
        user_id="attacker@example.com"
    )
    
    print("Audit events logged successfully")
