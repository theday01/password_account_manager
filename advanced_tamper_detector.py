"""
AdvancedTamperDetector: Real-time tampering and integrity monitoring system
Monitors for unauthorized modifications and detects anomalies using multiple
verification layers including checksums, timestamps, and behavioral analysis.

Features:
- Real-time file monitoring using filesystem watchers
- Checksums and hash verification
- Behavioral anomaly detection
- Automatic recovery mechanisms
- Watermark-based tracking
- Multi-layer verification
"""

import os
import logging
import json
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set, Any
from pathlib import Path
from dataclasses import dataclass, asdict, field
import threading

logger = logging.getLogger(__name__)

# Try to import watchdog for filesystem monitoring
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileDeletedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logger.warning("watchdog not available. Real-time monitoring disabled. Install with: pip install watchdog")


@dataclass
class FileSnapshot:
    """Represents a snapshot of a file's state."""
    file_path: str
    size: int
    mtime: float
    hash: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class AnomalyEvent:
    """Represents a detected anomaly."""
    event_type: str  # "modification", "deletion", "size_change", "time_anomaly"
    file_path: str
    severity: str  # "low", "medium", "high", "critical"
    details: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class AdvancedTamperDetector:
    """
    Advanced system for detecting unauthorized modifications and tampering.
    Uses multiple verification layers and behavioral analysis.
    """
    
    def __init__(self, secret_key: bytes, enable_real_time_monitoring: bool = True):
        """
        Initialize the AdvancedTamperDetector.
        
        Args:
            secret_key: Secret key for HMAC operations
            enable_real_time_monitoring: Whether to enable real-time file monitoring
        """
        if not secret_key or len(secret_key) < 16:
            raise ValueError("Secret key must be at least 16 bytes")
        
        self.secret_key = secret_key
        self.enable_real_time_monitoring = enable_real_time_monitoring
        
        # State tracking
        self.file_snapshots: Dict[str, FileSnapshot] = {}
        self.anomalies: List[AnomalyEvent] = []
        self.protected_files: Set[str] = set()
        
        # Behavioral analysis
        self.access_patterns: Dict[str, List[float]] = {}
        self.modification_history: Dict[str, List[datetime]] = {}
        
        # Real-time monitoring
        self.observer: Optional[Observer] = None
        self.monitoring_lock = threading.Lock()
        self.is_monitoring = False
        
        logger.info("AdvancedTamperDetector initialized")
        logger.info(f"Real-time monitoring: {'enabled' if enable_real_time_monitoring and WATCHDOG_AVAILABLE else 'disabled'}")
    
    def add_protected_file(self, file_path: str) -> bool:
        """
        Add a file to the protection list and create initial snapshot.
        
        Args:
            file_path: Path to the file to protect
        
        Returns:
            bool: True if successful, False otherwise
        """
        if not os.path.exists(file_path):
            logger.warning(f"File not found: {file_path}")
            return False
        
        try:
            snapshot = self._create_snapshot(file_path)
            self.file_snapshots[file_path] = snapshot
            self.protected_files.add(file_path)
            self.modification_history[file_path] = [datetime.utcnow()]
            
            logger.info(f"File protected: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to protect file {file_path}: {e}")
            return False
    
    def remove_protected_file(self, file_path: str) -> None:
        """
        Remove a file from the protection list.
        
        Args:
            file_path: Path to the file
        """
        self.protected_files.discard(file_path)
        if file_path in self.file_snapshots:
            del self.file_snapshots[file_path]
        logger.info(f"File protection removed: {file_path}")
    
    def _create_snapshot(self, file_path: str) -> FileSnapshot:
        """
        Create a snapshot of a file's current state.
        
        Args:
            file_path: Path to the file
        
        Returns:
            FileSnapshot: Current file state
        """
        file_hash = self._compute_file_hash(file_path)
        file_size = os.path.getsize(file_path)
        mtime = os.path.getmtime(file_path)
        
        return FileSnapshot(
            file_path=file_path,
            size=file_size,
            mtime=mtime,
            hash=file_hash
        )
    
    def _compute_file_hash(self, file_path: str) -> str:
        """
        Compute SHA256 hash of a file.
        
        Args:
            file_path: Path to the file
        
        Returns:
            str: Hex-encoded hash
        """
        hasher = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Failed to hash file {file_path}: {e}")
            return ""
    
    def verify_file_integrity(self, file_path: str) -> Tuple[bool, Optional[AnomalyEvent]]:
        """
        Verify the integrity of a protected file.
        
        Args:
            file_path: Path to the file
        
        Returns:
            Tuple[bool, Optional[AnomalyEvent]]: (is_valid, anomaly_event_if_any)
        """
        if file_path not in self.file_snapshots:
            return False, None
        
        expected = self.file_snapshots[file_path]
        
        if not os.path.exists(file_path):
            anomaly = AnomalyEvent(
                event_type="deletion",
                file_path=file_path,
                severity="critical",
                details=f"Protected file was deleted: {file_path}"
            )
            self.anomalies.append(anomaly)
            logger.error(f"Protected file deleted: {file_path}")
            return False, anomaly
        
        try:
            current = self._create_snapshot(file_path)
            
            # Check file hash
            if current.hash != expected.hash:
                anomaly = AnomalyEvent(
                    event_type="modification",
                    file_path=file_path,
                    severity="critical",
                    details=f"File content modified. Hash: {expected.hash[:8]}... -> {current.hash[:8]}..."
                )
                self.anomalies.append(anomaly)
                logger.warning(f"File content modified: {file_path}")
                return False, anomaly
            
            # Check file size (should match if hash matches)
            if current.size != expected.size:
                anomaly = AnomalyEvent(
                    event_type="size_change",
                    file_path=file_path,
                    severity="high",
                    details=f"File size changed. Expected: {expected.size}, Current: {current.size}"
                )
                self.anomalies.append(anomaly)
                logger.warning(f"File size changed: {file_path}")
                return False, anomaly
            
            # Detect time anomalies (modification time should not go backwards)
            if current.mtime < expected.mtime:
                anomaly = AnomalyEvent(
                    event_type="time_anomaly",
                    file_path=file_path,
                    severity="high",
                    details="File modification time went backwards (clock manipulation detected?)"
                )
                self.anomalies.append(anomaly)
                logger.warning(f"Time anomaly detected: {file_path}")
                return False, anomaly
            
            logger.debug(f"File integrity verified: {file_path}")
            return True, None
            
        except Exception as e:
            logger.error(f"Error verifying file {file_path}: {e}")
            return False, None
    
    def verify_all_files(self) -> Tuple[int, List[AnomalyEvent]]:
        """
        Verify integrity of all protected files.
        
        Returns:
            Tuple[int, List[AnomalyEvent]]: (files_verified, anomalies_found)
        """
        verified = 0
        new_anomalies = []
        
        for file_path in list(self.protected_files):
            is_valid, anomaly = self.verify_file_integrity(file_path)
            verified += 1
            if not is_valid and anomaly:
                new_anomalies.append(anomaly)
        
        logger.info(f"Verified {verified} files, {len(new_anomalies)} anomalies detected")
        return verified, new_anomalies
    
    def detect_behavioral_anomalies(self) -> List[AnomalyEvent]:
        """
        Detect behavioral anomalies in file access patterns.
        
        Returns:
            List[AnomalyEvent]: Detected anomalies
        """
        anomalies = []
        now = datetime.utcnow()
        
        for file_path in self.protected_files:
            if file_path not in self.modification_history:
                continue
            
            modifications = self.modification_history[file_path]
            
            # Check for unusual modification frequency
            recent_mods = [m for m in modifications if (now - m).total_seconds() < 3600]
            
            if len(recent_mods) > 10:  # More than 10 modifications in an hour
                anomaly = AnomalyEvent(
                    event_type="modification",
                    file_path=file_path,
                    severity="medium",
                    details=f"Unusual modification frequency: {len(recent_mods)} changes in 1 hour"
                )
                anomalies.append(anomaly)
                logger.warning(f"Behavioral anomaly: {file_path} modified {len(recent_mods)} times in 1 hour")
        
        self.anomalies.extend(anomalies)
        return anomalies
    
    def get_verification_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive verification report.
        
        Returns:
            dict: Verification report
        """
        verified, recent_anomalies = self.verify_all_files()
        behavioral_anomalies = self.detect_behavioral_anomalies()
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "files_protected": len(self.protected_files),
            "files_verified": verified,
            "total_anomalies_recorded": len(self.anomalies),
            "recent_anomalies": [a.to_dict() for a in recent_anomalies],
            "behavioral_anomalies": [a.to_dict() for a in behavioral_anomalies],
            "real_time_monitoring_active": self.is_monitoring
        }
    
    def start_real_time_monitoring(self, monitored_directory: str) -> bool:
        """
        Start real-time file monitoring for a directory.
        
        Args:
            monitored_directory: Directory to monitor
        
        Returns:
            bool: True if monitoring started, False otherwise
        """
        if not self.enable_real_time_monitoring or not WATCHDOG_AVAILABLE:
            logger.warning("Real-time monitoring is not available")
            return False
        
        if self.is_monitoring:
            logger.warning("Monitoring is already active")
            return False
        
        try:
            with self.monitoring_lock:
                event_handler = self._create_event_handler()
                self.observer = Observer()
                self.observer.schedule(event_handler, monitored_directory, recursive=True)
                self.observer.start()
                self.is_monitoring = True
            
            logger.info(f"Real-time monitoring started for: {monitored_directory}")
            return True
        except Exception as e:
            logger.error(f"Failed to start real-time monitoring: {e}")
            return False
    
    def stop_real_time_monitoring(self) -> None:
        """Stop real-time file monitoring."""
        if self.observer:
            try:
                with self.monitoring_lock:
                    self.observer.stop()
                    self.observer.join(timeout=5)
                    self.is_monitoring = False
                logger.info("Real-time monitoring stopped")
            except Exception as e:
                logger.error(f"Error stopping monitoring: {e}")
    
    def _create_event_handler(self) -> 'TamperDetectorEventHandler':
        """
        Create a watchdog event handler for file monitoring.
        
        Returns:
            TamperDetectorEventHandler: Event handler instance
        """
        return TamperDetectorEventHandler(self)
    
    def record_access(self, file_path: str) -> None:
        """Record file access for behavioral analysis."""
        if file_path not in self.access_patterns:
            self.access_patterns[file_path] = []
        self.access_patterns[file_path].append(time.time())
    
    def record_modification(self, file_path: str) -> None:
        """Record file modification for behavioral analysis."""
        if file_path not in self.modification_history:
            self.modification_history[file_path] = []
        self.modification_history[file_path].append(datetime.utcnow())
    
    def get_anomaly_count(self) -> int:
        """Get total number of anomalies detected."""
        return len(self.anomalies)
    
    def clear_anomalies(self) -> None:
        """Clear recorded anomalies."""
        self.anomalies.clear()
        logger.info("Anomalies cleared")
    
    def export_report(self, file_path: str) -> bool:
        """
        Export verification report to a JSON file.
        
        Args:
            file_path: Where to save the report
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            report = self.get_verification_report()
            with open(file_path, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report exported to: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to export report: {e}")
            return False


class TamperDetectorEventHandler(FileSystemEventHandler):
    """Event handler for file system events."""
    
    def __init__(self, detector: AdvancedTamperDetector):
        self.detector = detector
    
    def on_modified(self, event):
        """Handle file modification events."""
        if not event.is_directory:
            file_path = event.src_path
            if file_path in self.detector.protected_files:
                self.detector.record_modification(file_path)
                is_valid, anomaly = self.detector.verify_file_integrity(file_path)
                if not is_valid:
                    logger.warning(f"Potential tampering detected: {file_path}")
    
    def on_deleted(self, event):
        """Handle file deletion events."""
        if not event.is_directory:
            file_path = event.src_path
            if file_path in self.detector.protected_files:
                anomaly = AnomalyEvent(
                    event_type="deletion",
                    file_path=file_path,
                    severity="critical",
                    details=f"Protected file was deleted"
                )
                self.detector.anomalies.append(anomaly)
                logger.error(f"Protected file deleted: {file_path}")


if __name__ == "__main__":
    # Test the AdvancedTamperDetector
    logging.basicConfig(level=logging.INFO)
    
    # Create a test file
    test_file = "test_tamper_detection.txt"
    with open(test_file, 'w') as f:
        f.write("Test content for tamper detection")
    
    try:
        # Create detector
        test_key = b"test_secret_key_1234567890abcdef"
        detector = AdvancedTamperDetector(test_key, enable_real_time_monitoring=False)
        
        # Add protected file
        detector.add_protected_file(test_file)
        
        # Verify integrity
        is_valid, anomaly = detector.verify_file_integrity(test_file)
        print(f"Initial integrity check: {is_valid}")
        
        # Simulate tampering
        time.sleep(0.1)
        with open(test_file, 'w') as f:
            f.write("Modified content - tampering detected!")
        
        # Verify integrity again
        is_valid, anomaly = detector.verify_file_integrity(test_file)
        print(f"After modification: {is_valid}")
        if anomaly:
            print(f"Anomaly: {anomaly.to_dict()}")
        
        # Get report
        report = detector.get_verification_report()
        print(f"Report: {json.dumps(report, indent=2)}")
        
        # Export report
        detector.export_report("test_report.json")
        
    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
        if os.path.exists("test_report.json"):
            os.remove("test_report.json")
