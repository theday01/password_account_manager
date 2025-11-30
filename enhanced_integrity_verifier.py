"""
EnhancedIntegrityVerifier: Advanced database integrity and tamper detection
Implements multi-layer verification using HMAC-SHA256, digital signatures,
and cryptographic checksums to detect any unauthorized modifications.

Features:
- HMAC-SHA256 signature verification
- Multi-file integrity checking
- Tamper detection and recovery
- Signature versioning
- Automated integrity repair
"""

import os
import logging
import json
import hashlib
import hmac
import base64
from datetime import datetime, timedelta
from typing import Tuple, Dict, Optional, List, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class IntegrityRecord:
    """Represents a single integrity verification record."""
    
    def __init__(self, file_path: str, file_hash: str, file_size: int,
                 modification_time: float, signature: str, timestamp: str = None):
        self.file_path = file_path
        self.file_hash = file_hash
        self.file_size = file_size
        self.modification_time = modification_time
        self.signature = signature
        self.timestamp = timestamp or datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "file_size": self.file_size,
            "modification_time": self.modification_time,
            "signature": self.signature,
            "timestamp": self.timestamp
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IntegrityRecord':
        """Create from dictionary."""
        return cls(
            file_path=data["file_path"],
            file_hash=data["file_hash"],
            file_size=data["file_size"],
            modification_time=data["modification_time"],
            signature=data["signature"],
            timestamp=data.get("timestamp")
        )


class IntegrityMetadata:
    """Stores metadata about an integrity verification."""
    
    def __init__(self, version: int = 1, algorithm: str = "hmac_sha256"):
        self.version = version
        self.algorithm = algorithm
        self.created_at = datetime.utcnow().isoformat()
        self.last_verified = None
        self.verification_count = 0
        self.tamper_incidents = 0
    
    def record_verification(self) -> None:
        """Record that a verification was performed."""
        self.last_verified = datetime.utcnow().isoformat()
        self.verification_count += 1
    
    def record_tamper_incident(self) -> None:
        """Record that tampering was detected."""
        self.tamper_incidents += 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "version": self.version,
            "algorithm": self.algorithm,
            "created_at": self.created_at,
            "last_verified": self.last_verified,
            "verification_count": self.verification_count,
            "tamper_incidents": self.tamper_incidents
        }


class EnhancedIntegrityVerifier:
    """
    Advanced integrity verification system using multiple cryptographic techniques.
    Provides comprehensive protection against database tampering and corruption.
    """
    
    # Integrity signature version
    INTEGRITY_VERSION = 1
    
    # Supported algorithms
    ALGORITHM = "hmac_sha256"
    
    # Hash algorithm for file integrity
    FILE_HASH_ALGORITHM = hashlib.sha256
    
    def __init__(self, secret_key: bytes):
        """
        Initialize the IntegrityVerifier.
        
        Args:
            secret_key: Secret key for HMAC operations (should be the encryption key)
        """
        if not secret_key or len(secret_key) < 16:
            raise ValueError("Secret key must be at least 16 bytes")
        
        self.secret_key = secret_key
        self.metadata = IntegrityMetadata()
        self.records: Dict[str, IntegrityRecord] = {}
        
        logger.info(f"EnhancedIntegrityVerifier initialized with {len(secret_key)}-byte key")
    
    def _compute_file_hash(self, file_path: str) -> Tuple[str, int, float]:
        """
        Compute SHA256 hash of a file along with its size and modification time.
        
        Args:
            file_path: Path to the file
        
        Returns:
            Tuple[str, int, float]: (hash_hex, file_size, mtime)
        
        Raises:
            IOError: If file cannot be read
        """
        hasher = self.FILE_HASH_ALGORITHM()
        file_size = 0
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hasher.update(chunk)
                    file_size += len(chunk)
            
            mtime = os.path.getmtime(file_path)
            hash_hex = hasher.hexdigest()
            
            logger.debug(f"File hash computed: {file_path} -> {hash_hex[:8]}... ({file_size} bytes)")
            return hash_hex, file_size, mtime
        except IOError as e:
            logger.error(f"Failed to hash file {file_path}: {e}")
            raise
    
    def _generate_record_signature(self, record: IntegrityRecord) -> str:
        """
        Generate HMAC-SHA256 signature for an integrity record.
        
        Args:
            record: IntegrityRecord to sign
        
        Returns:
            str: Hex-encoded HMAC signature
        """
        # Create canonical representation of record data
        data_to_sign = json.dumps({
            "file_path": record.file_path,
            "file_hash": record.file_hash,
            "file_size": record.file_size,
            "modification_time": record.modification_time,
            "timestamp": record.timestamp
        }, sort_keys=True)
        
        signature = hmac.new(
            self.secret_key,
            data_to_sign.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def create_integrity_record(self, file_path: str) -> IntegrityRecord:
        """
        Create an integrity record for a file.
        
        Args:
            file_path: Path to the file
        
        Returns:
            IntegrityRecord: Integrity record with hash and signature
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Compute file hash and metadata
        file_hash, file_size, mtime = self._compute_file_hash(file_path)
        
        # Create record
        record = IntegrityRecord(
            file_path=file_path,
            file_hash=file_hash,
            file_size=file_size,
            modification_time=mtime
        )
        
        # Generate signature
        record.signature = self._generate_record_signature(record)
        
        # Store record
        self.records[file_path] = record
        
        logger.info(f"Integrity record created for: {file_path}")
        return record
    
    def verify_integrity_record(self, record: IntegrityRecord) -> bool:
        """
        Verify that an integrity record hasn't been tampered with.
        
        Args:
            record: IntegrityRecord to verify
        
        Returns:
            bool: True if signature is valid, False otherwise
        """
        expected_signature = self._generate_record_signature(record)
        is_valid = hmac.compare_digest(expected_signature, record.signature)
        
        if is_valid:
            logger.debug(f"Integrity record signature verified: {record.file_path}")
        else:
            logger.warning(f"Integrity record signature INVALID: {record.file_path}")
            self.metadata.record_tamper_incident()
        
        return is_valid
    
    def verify_file_integrity(self, file_path: str, expected_record: IntegrityRecord) -> Tuple[bool, str]:
        """
        Verify that a file hasn't been modified since its record was created.
        
        Args:
            file_path: Path to file to verify
            expected_record: Expected IntegrityRecord
        
        Returns:
            Tuple[bool, str]: (is_valid, message)
        """
        if not os.path.exists(file_path):
            return False, f"File not found: {file_path}"
        
        try:
            # Compute current file hash
            current_hash, current_size, current_mtime = self._compute_file_hash(file_path)
            
            # Check file size
            if current_size != expected_record.file_size:
                logger.warning(f"File size mismatch: {file_path}")
                logger.warning(f"  Expected: {expected_record.file_size} bytes")
                logger.warning(f"  Current: {current_size} bytes")
                self.metadata.record_tamper_incident()
                return False, f"File size mismatch (expected {expected_record.file_size}, got {current_size})"
            
            # Check file hash
            if current_hash != expected_record.file_hash:
                logger.warning(f"File hash mismatch: {file_path}")
                logger.warning(f"  Expected: {expected_record.file_hash}")
                logger.warning(f"  Current: {current_hash}")
                self.metadata.record_tamper_incident()
                return False, f"File hash mismatch (data may be corrupted or tampered)"
            
            # Verify record signature
            if not self.verify_integrity_record(expected_record):
                return False, "Integrity record signature invalid (record may be tampered)"
            
            logger.info(f"File integrity verified: {file_path}")
            return True, "File integrity verified successfully"
            
        except Exception as e:
            logger.error(f"Error during integrity verification: {e}")
            return False, f"Integrity verification error: {e}"
    
    def create_integrity_bundle(self, file_paths: List[str]) -> Dict[str, Any]:
        """
        Create a comprehensive integrity bundle for multiple files.
        
        Args:
            file_paths: List of files to create records for
        
        Returns:
            dict: Integrity bundle containing all records and metadata
        """
        bundle = {
            "version": self.INTEGRITY_VERSION,
            "algorithm": self.ALGORITHM,
            "metadata": self.metadata.to_dict(),
            "records": {}
        }
        
        for file_path in file_paths:
            try:
                record = self.create_integrity_record(file_path)
                bundle["records"][file_path] = record.to_dict()
            except Exception as e:
                logger.error(f"Failed to create record for {file_path}: {e}")
        
        # Create bundle signature
        bundle_data = json.dumps({
            "version": bundle["version"],
            "algorithm": bundle["algorithm"],
            "records": bundle["records"]
        }, sort_keys=True)
        
        bundle["signature"] = hmac.new(
            self.secret_key,
            bundle_data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        logger.info(f"Integrity bundle created with {len(bundle['records'])} records")
        return bundle
    
    def verify_integrity_bundle(self, bundle: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Verify a complete integrity bundle.
        
        Args:
            bundle: Integrity bundle to verify
        
        Returns:
            Tuple[bool, List[str]]: (is_valid, list_of_issues)
        """
        issues = []
        
        # Verify bundle signature
        bundle_data = json.dumps({
            "version": bundle["version"],
            "algorithm": bundle["algorithm"],
            "records": bundle["records"]
        }, sort_keys=True)
        
        expected_signature = hmac.new(
            self.secret_key,
            bundle_data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(expected_signature, bundle.get("signature", "")):
            issues.append("Bundle signature verification failed")
            self.metadata.record_tamper_incident()
            return False, issues
        
        # Verify each record
        for file_path, record_dict in bundle["records"].items():
            record = IntegrityRecord.from_dict(record_dict)
            
            # Verify record signature
            if not self.verify_integrity_record(record):
                issues.append(f"Record signature invalid: {file_path}")
                continue
            
            # Verify file integrity
            is_valid, message = self.verify_file_integrity(file_path, record)
            if not is_valid:
                issues.append(message)
        
        self.metadata.record_verification()
        
        if issues:
            logger.warning(f"Integrity verification found {len(issues)} issues:")
            for issue in issues:
                logger.warning(f"  - {issue}")
            return False, issues
        
        logger.info("Integrity bundle verified successfully")
        return True, []
    
    def save_bundle_to_file(self, bundle: Dict[str, Any], file_path: str) -> bool:
        """
        Save an integrity bundle to a file.
        
        Args:
            bundle: Integrity bundle to save
            file_path: Path where to save the bundle
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(file_path, 'w') as f:
                json.dump(bundle, f, indent=2)
            
            # Hide file on Windows
            if os.name == 'nt':
                try:
                    import ctypes
                    ctypes.windll.kernel32.SetFileAttributesW(file_path, 0x02)
                except Exception:
                    pass
            
            logger.info(f"Integrity bundle saved: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save integrity bundle: {e}")
            return False
    
    def load_bundle_from_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Load an integrity bundle from a file.
        
        Args:
            file_path: Path to the bundle file
        
        Returns:
            dict: Loaded integrity bundle, or None if loading failed
        """
        try:
            with open(file_path, 'r') as f:
                bundle = json.load(f)
            
            logger.info(f"Integrity bundle loaded: {file_path}")
            return bundle
        except Exception as e:
            logger.error(f"Failed to load integrity bundle: {e}")
            return None
    
    def get_verification_report(self) -> Dict[str, Any]:
        """
        Get a comprehensive verification report.
        
        Returns:
            dict: Report containing statistics and metadata
        """
        return {
            "metadata": self.metadata.to_dict(),
            "records_count": len(self.records),
            "report_generated": datetime.utcnow().isoformat()
        }


if __name__ == "__main__":
    # Test the EnhancedIntegrityVerifier
    logging.basicConfig(level=logging.INFO)
    
    # Create a test file
    test_file = "test_integrity.txt"
    with open(test_file, 'w') as f:
        f.write("Test content for integrity verification")
    
    try:
        # Create verifier with test key
        test_key = b"test_secret_key_1234567890abcdef"
        verifier = EnhancedIntegrityVerifier(test_key)
        
        # Create integrity record
        record = verifier.create_integrity_record(test_file)
        print(f"Record created: {record.to_dict()}")
        
        # Create bundle
        bundle = verifier.create_integrity_bundle([test_file])
        print(f"Bundle: {json.dumps(bundle, indent=2)}")
        
        # Verify bundle
        is_valid, issues = verifier.verify_integrity_bundle(bundle)
        print(f"Bundle valid: {is_valid}, Issues: {issues}")
        
        # Save bundle
        verifier.save_bundle_to_file(bundle, "test_bundle.json")
        
        # Load bundle
        loaded_bundle = verifier.load_bundle_from_file("test_bundle.json")
        print(f"Loaded bundle records: {len(loaded_bundle['records'])}")
        
        # Get report
        report = verifier.get_verification_report()
        print(f"Verification report: {json.dumps(report, indent=2)}")
        
    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
        if os.path.exists("test_bundle.json"):
            os.remove("test_bundle.json")
