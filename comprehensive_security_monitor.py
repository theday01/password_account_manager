"""
ComprehensiveSecurityMonitor: Real-time security monitoring and anomaly detection
Provides centralized security event tracking, analysis, and alerting.

Features:
- Real-time security event logging
- Anomaly detection and alerting
- Security metrics and analytics
- Incident tracking and response
- Multi-layer threat detection
- Automated security reports
"""

import os
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict, field
from enum import Enum
import threading
import statistics

logger = logging.getLogger(__name__)


class SecurityEventType(Enum):
    """Types of security events."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ENCRYPTION = "encryption"
    INTEGRITY = "integrity"
    TAMPERING = "tampering"
    CLIPBOARD = "clipboard"
    FILE_ACCESS = "file_access"
    CONFIGURATION = "configuration"
    SYSTEM = "system"
    ANOMALY = "anomaly"


class SecuritySeverity(Enum):
    """Security event severity levels."""
    INFO = 1
    WARNING = 2
    CRITICAL = 3
    ALERT = 4


@dataclass
class SecurityEvent:
    """Represents a security event."""
    event_type: SecurityEventType
    severity: SecuritySeverity
    message: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    component: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    resolved: bool = False
    resolution_details: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_type": self.event_type.value,
            "severity": self.severity.name,
            "message": self.message,
            "timestamp": self.timestamp,
            "component": self.component,
            "details": self.details,
            "resolved": self.resolved,
            "resolution_details": self.resolution_details
        }


@dataclass
class SecurityMetrics:
    """Aggregated security metrics."""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    total_events: int = 0
    events_by_severity: Dict[str, int] = field(default_factory=lambda: {
        "INFO": 0, "WARNING": 0, "CRITICAL": 0, "ALERT": 0
    })
    events_by_type: Dict[str, int] = field(default_factory=dict)
    authentication_attempts: int = 0
    authentication_failures: int = 0
    integrity_checks: int = 0
    integrity_failures: int = 0
    tampering_incidents: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class ComprehensiveSecurityMonitor:
    """
    Centralized security monitoring and anomaly detection system.
    Tracks all security-related events and analyzes patterns.
    """
    
    # Event retention (keep events for this long)
    EVENT_RETENTION_PERIOD = timedelta(days=90)
    
    # Threshold for anomaly detection
    ANOMALY_THRESHOLD = 0.05  # 5% deviation
    
    # Time window for trend analysis
    TREND_WINDOW = timedelta(hours=24)
    
    def __init__(self, enable_threat_analysis: bool = True):
        """
        Initialize the ComprehensiveSecurityMonitor.
        
        Args:
            enable_threat_analysis: Whether to enable advanced threat analysis
        """
        self.enable_threat_analysis = enable_threat_analysis
        
        # Event storage
        self.events: List[SecurityEvent] = []
        self.critical_incidents: List[SecurityEvent] = []
        
        # Metrics
        self.metrics = SecurityMetrics()
        
        # Threat analysis
        self.baseline_patterns: Dict[str, Any] = {}
        self.anomaly_detections: List[Dict[str, Any]] = []
        self.threat_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
        
        # Monitoring state
        self.is_monitoring = False
        self.monitoring_lock = threading.Lock()
        
        # Alert callbacks
        self.alert_callbacks: List[callable] = []
        
        logger.info("ComprehensiveSecurityMonitor initialized")
        logger.info(f"Threat analysis enabled: {enable_threat_analysis}")
    
    def log_event(self, event_type: SecurityEventType, severity: SecuritySeverity,
                  message: str, component: str = None, details: Dict = None) -> SecurityEvent:
        """
        Log a security event.
        
        Args:
            event_type: Type of security event
            severity: Severity level
            message: Event message
            component: Component that generated the event
            details: Additional details
        
        Returns:
            SecurityEvent: The logged event
        """
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            message=message,
            component=component,
            details=details or {}
        )
        
        # Add to events
        self.events.append(event)
        
        # Update metrics
        self.metrics.total_events += 1
        self.metrics.events_by_severity[severity.name] += 1
        
        event_type_str = event_type.value
        if event_type_str not in self.metrics.events_by_type:
            self.metrics.events_by_type[event_type_str] = 0
        self.metrics.events_by_type[event_type_str] += 1
        
        # Track critical incidents
        if severity in [SecuritySeverity.CRITICAL, SecuritySeverity.ALERT]:
            self.critical_incidents.append(event)
            self._trigger_alerts(event)
        
        # Log appropriately
        if severity == SecuritySeverity.ALERT:
            logger.critical(f"SECURITY ALERT: {message}")
        elif severity == SecuritySeverity.CRITICAL:
            logger.critical(f"CRITICAL: {message}")
        elif severity == SecuritySeverity.WARNING:
            logger.warning(message)
        else:
            logger.info(message)
        
        # Run threat analysis
        if self.enable_threat_analysis:
            self._analyze_threat_level()
        
        return event
    
    def log_authentication_attempt(self, success: bool, component: str = None) -> SecurityEvent:
        """
        Log an authentication attempt.
        
        Args:
            success: Whether authentication was successful
            component: Component that performed authentication
        
        Returns:
            SecurityEvent: The logged event
        """
        self.metrics.authentication_attempts += 1
        
        if not success:
            self.metrics.authentication_failures += 1
            severity = SecuritySeverity.WARNING if self.metrics.authentication_failures < 5 else SecuritySeverity.CRITICAL
            message = f"Authentication failed (attempt #{self.metrics.authentication_failures})"
        else:
            message = "Authentication successful"
            severity = SecuritySeverity.INFO
        
        return self.log_event(
            event_type=SecurityEventType.AUTHENTICATION,
            severity=severity,
            message=message,
            component=component,
            details={
                "success": success,
                "total_attempts": self.metrics.authentication_attempts,
                "total_failures": self.metrics.authentication_failures
            }
        )
    
    def log_integrity_check(self, success: bool, component: str = None, 
                           details: Dict = None) -> SecurityEvent:
        """
        Log an integrity verification.
        
        Args:
            success: Whether integrity check passed
            component: Component that performed the check
            details: Check details
        
        Returns:
            SecurityEvent: The logged event
        """
        self.metrics.integrity_checks += 1
        
        if not success:
            self.metrics.integrity_failures += 1
            severity = SecuritySeverity.CRITICAL
            message = "Integrity check FAILED - Data may be corrupted or tampered"
        else:
            severity = SecuritySeverity.INFO
            message = "Integrity check passed"
        
        return self.log_event(
            event_type=SecurityEventType.INTEGRITY,
            severity=severity,
            message=message,
            component=component,
            details={
                **(details or {}),
                "success": success,
                "total_checks": self.metrics.integrity_checks,
                "total_failures": self.metrics.integrity_failures
            }
        )
    
    def log_tampering_incident(self, incident_type: str, component: str = None,
                              details: Dict = None) -> SecurityEvent:
        """
        Log a tampering incident.
        
        Args:
            incident_type: Type of tampering detected
            component: Component that detected tampering
            details: Incident details
        
        Returns:
            SecurityEvent: The logged event
        """
        self.metrics.tampering_incidents += 1
        
        message = f"TAMPERING DETECTED: {incident_type}"
        
        return self.log_event(
            event_type=SecurityEventType.TAMPERING,
            severity=SecuritySeverity.ALERT,
            message=message,
            component=component,
            details={
                **(details or {}),
                "incident_type": incident_type,
                "total_incidents": self.metrics.tampering_incidents
            }
        )
    
    def _analyze_threat_level(self) -> None:
        """Analyze current threat level based on recent events."""
        if not self.enable_threat_analysis:
            return
        
        now = datetime.utcnow()
        recent_events = [
            e for e in self.events
            if datetime.fromisoformat(e.timestamp) > now - self.TREND_WINDOW
        ]
        
        # Count critical events
        critical_count = sum(
            1 for e in recent_events
            if e.severity in [SecuritySeverity.CRITICAL, SecuritySeverity.ALERT]
        )
        
        # Count warnings
        warning_count = sum(
            1 for e in recent_events
            if e.severity == SecuritySeverity.WARNING
        )
        
        # Determine threat level
        if critical_count > 0:
            self.threat_level = "CRITICAL"
        elif warning_count > 10 or critical_count > 5:
            self.threat_level = "HIGH"
        elif warning_count > 5:
            self.threat_level = "MEDIUM"
        else:
            self.threat_level = "LOW"
        
        logger.debug(f"Threat level updated: {self.threat_level} (Critical: {critical_count}, Warnings: {warning_count})")
    
    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """
        Detect anomalies in security event patterns.
        
        Returns:
            list: Detected anomalies
        """
        if not self.enable_threat_analysis:
            return []
        
        anomalies = []
        
        # Detect unusual authentication patterns
        auth_events = [
            e for e in self.events
            if e.event_type == SecurityEventType.AUTHENTICATION
        ]
        
        if len(auth_events) > 10:
            # Check for failed authentication rate
            failed_rate = self.metrics.authentication_failures / self.metrics.authentication_attempts
            if failed_rate > 0.3:  # More than 30% failure rate
                anomalies.append({
                    "type": "high_authentication_failure_rate",
                    "severity": "HIGH",
                    "details": f"Authentication failure rate: {failed_rate:.1%}",
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        # Detect integrity check failures
        if self.metrics.integrity_failures > 0:
            failure_rate = self.metrics.integrity_failures / self.metrics.integrity_checks
            if failure_rate > 0.1:  # More than 10% failure rate
                anomalies.append({
                    "type": "high_integrity_failure_rate",
                    "severity": "CRITICAL",
                    "details": f"Integrity failure rate: {failure_rate:.1%}",
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        # Detect rapid event sequences
        now = datetime.utcnow()
        recent_critical = [
            e for e in self.events
            if e.severity == SecuritySeverity.CRITICAL and
               datetime.fromisoformat(e.timestamp) > now - timedelta(minutes=1)
        ]
        
        if len(recent_critical) > 5:
            anomalies.append({
                "type": "critical_event_burst",
                "severity": "CRITICAL",
                "details": f"{len(recent_critical)} critical events in last minute",
                "timestamp": datetime.utcnow().isoformat()
            })
        
        self.anomaly_detections.extend(anomalies)
        return anomalies
    
    def _trigger_alerts(self, event: SecurityEvent) -> None:
        """Trigger alert callbacks for critical events."""
        for callback in self.alert_callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
    
    def register_alert_callback(self, callback: callable) -> None:
        """
        Register a callback for critical alerts.
        
        Args:
            callback: Function to call on critical events
        """
        self.alert_callbacks.append(callback)
        logger.info("Alert callback registered")
    
    def resolve_incident(self, event: SecurityEvent, resolution: str) -> None:
        """
        Mark an incident as resolved.
        
        Args:
            event: Event to resolve
            resolution: Resolution details
        """
        event.resolved = True
        event.resolution_details = resolution
        logger.info(f"Incident resolved: {resolution}")
    
    def get_security_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive security report.
        
        Returns:
            dict: Security report
        """
        anomalies = self.detect_anomalies()
        
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "threat_level": self.threat_level,
            "metrics": self.metrics.to_dict(),
            "recent_events": [e.to_dict() for e in self.events[-20:]],
            "critical_incidents": [e.to_dict() for e in self.critical_incidents],
            "unresolved_incidents": len([e for e in self.critical_incidents if not e.resolved]),
            "anomalies_detected": len(anomalies),
            "recent_anomalies": anomalies[-10:]
        }
        
        return report
    
    def get_events_by_type(self, event_type: SecurityEventType, 
                          limit: int = 50) -> List[SecurityEvent]:
        """
        Get events of a specific type.
        
        Args:
            event_type: Type of events to retrieve
            limit: Maximum number of events
        
        Returns:
            list: Events of the specified type
        """
        return [
            e for e in self.events[-limit:]
            if e.event_type == event_type
        ]
    
    def cleanup_old_events(self) -> int:
        """
        Remove old events based on retention period.
        
        Returns:
            int: Number of events removed
        """
        cutoff = datetime.utcnow() - self.EVENT_RETENTION_PERIOD
        original_count = len(self.events)
        
        self.events = [
            e for e in self.events
            if datetime.fromisoformat(e.timestamp) > cutoff
        ]
        
        removed = original_count - len(self.events)
        logger.info(f"Cleaned up {removed} old events")
        return removed
    
    def export_report(self, file_path: str) -> bool:
        """
        Export security report to JSON file.
        
        Args:
            file_path: Where to save the report
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            report = self.get_security_report()
            with open(file_path, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Security report exported to: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to export security report: {e}")
            return False
    
    def get_summary(self) -> str:
        """
        Get a text summary of security status.
        
        Returns:
            str: Summary text
        """
        summary = f"""
SECURITY MONITOR SUMMARY
========================
Threat Level: {self.threat_level}
Total Events: {self.metrics.total_events}
Critical Incidents: {len(self.critical_incidents)}
Unresolved Incidents: {len([e for e in self.critical_incidents if not e.resolved])}
Tampering Incidents: {self.metrics.tampering_incidents}
Integrity Failures: {self.metrics.integrity_failures}/{self.metrics.integrity_checks}
Auth Failures: {self.metrics.authentication_failures}/{self.metrics.authentication_attempts}
Recent Anomalies: {len(self.anomaly_detections)}
"""
        return summary


if __name__ == "__main__":
    # Test the ComprehensiveSecurityMonitor
    logging.basicConfig(level=logging.INFO)
    
    monitor = ComprehensiveSecurityMonitor(enable_threat_analysis=True)
    
    print("=== Comprehensive Security Monitor Test ===\n")
    
    # Log various events
    print("1. Logging authentication events...")
    monitor.log_authentication_attempt(True, "login_system")
    monitor.log_authentication_attempt(False, "login_system")
    monitor.log_authentication_attempt(False, "login_system")
    
    print("\n2. Logging integrity checks...")
    monitor.log_integrity_check(True, "database", {"database": "credentials.db"})
    
    print("\n3. Logging tampering incident...")
    monitor.log_tampering_incident("file_hash_mismatch", "integrity_verifier", 
                                   {"file": "sensitive.db"})
    
    print("\n4. Detecting anomalies...")
    anomalies = monitor.detect_anomalies()
    print(f"   Found {len(anomalies)} anomalies")
    
    print("\n5. Security report:")
    report = monitor.get_security_report()
    print(f"   Threat level: {report['threat_level']}")
    print(f"   Critical incidents: {len(report['critical_incidents'])}")
    
    print("\n6. Summary:")
    print(monitor.get_summary())
    
    print("\n7. Exporting report...")
    monitor.export_report("security_report.json")
    
    print("Done!")
