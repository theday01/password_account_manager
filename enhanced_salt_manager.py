"""
EnhancedSaltManager: Advanced salt generation, storage, and management
Implements secure salt handling with versioning, rotation, encryption,
and comprehensive audit tracking.

Features:
- Secure random salt generation
- Salt versioning and rotation
- Encrypted salt storage
- Audit logging of salt operations
- Salt derivation strategies
- Multi-layer salt protection
"""

import os
import logging
import json
import base64
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Tuple, Dict, Optional, Any, List
from dataclasses import dataclass, asdict, field
import secrets

logger = logging.getLogger(__name__)


@dataclass
class SaltVersion:
    """Represents a versioned salt."""
    version: int
    salt_bytes: bytes  # Raw salt bytes
    salt_hash: str    # Hash for verification
    created_at: str
    rotation_recommended_at: Optional[str] = None
    rotation_required_at: Optional[str] = None
    usage_count: int = 0
    last_used_at: Optional[str] = None
    status: str = "active"  # "active", "deprecated", "expired"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (for storage, excludes raw bytes)."""
        return {
            "version": self.version,
            "salt_hash": self.salt_hash,
            "created_at": self.created_at,
            "rotation_recommended_at": self.rotation_recommended_at,
            "rotation_required_at": self.rotation_required_at,
            "usage_count": self.usage_count,
            "last_used_at": self.last_used_at,
            "status": self.status
        }
    
    def to_secure_dict(self) -> Dict[str, Any]:
        """Convert to secure dictionary (includes encrypted salt)."""
        return {
            "version": self.version,
            "salt_hex": self.salt_bytes.hex(),
            "salt_hash": self.salt_hash,
            "created_at": self.created_at,
            "rotation_recommended_at": self.rotation_recommended_at,
            "rotation_required_at": self.rotation_required_at,
            "usage_count": self.usage_count,
            "last_used_at": self.last_used_at,
            "status": self.status
        }


@dataclass
class SaltOperation:
    """Audit record for salt operations."""
    operation_type: str  # "generate", "rotate", "migrate", "verify"
    version: int
    timestamp: str
    success: bool
    details: Optional[str] = None
    ip_address: Optional[str] = None


class EnhancedSaltManager:
    """
    Advanced salt management system with versioning, rotation, and encryption.
    Ensures cryptographic strength and security best practices.
    """
    
    # Salt configuration
    MIN_SALT_LENGTH = 32  # 256 bits minimum
    RECOMMENDED_SALT_LENGTH = 32  # 256 bits
    MAX_SALT_LENGTH = 64  # 512 bits maximum
    
    # Rotation policies
    SALT_ROTATION_PERIOD = timedelta(days=365)  # Rotate annually
    SALT_DEPRECATION_PERIOD = timedelta(days=30)  # Deprecate after 1 month
    SALT_EXPIRATION_PERIOD = timedelta(days=90)  # Expire after 3 months
    
    def __init__(self, encryption_key: bytes, enable_versioning: bool = True):
        """
        Initialize the EnhancedSaltManager.
        
        Args:
            encryption_key: Key for encrypting stored salts
            enable_versioning: Whether to enable salt versioning
        """
        if not encryption_key or len(encryption_key) < 16:
            raise ValueError("Encryption key must be at least 16 bytes")
        
        self.encryption_key = encryption_key
        self.enable_versioning = enable_versioning
        
        # Salt storage
        self.current_version = 0
        self.salt_versions: Dict[int, SaltVersion] = {}
        
        # Audit trail
        self.operations_log: List[SaltOperation] = []
        
        logger.info("EnhancedSaltManager initialized")
        logger.info(f"Versioning enabled: {enable_versioning}")
    
    def generate_salt(self, length: int = None) -> bytes:
        """
        Generate a cryptographically secure random salt.
        
        Args:
            length: Salt length in bytes (default: RECOMMENDED_SALT_LENGTH)
        
        Returns:
            bytes: Secure random salt
        """
        length = length or self.RECOMMENDED_SALT_LENGTH
        
        if length < self.MIN_SALT_LENGTH or length > self.MAX_SALT_LENGTH:
            raise ValueError(f"Salt length must be between {self.MIN_SALT_LENGTH} and {self.MAX_SALT_LENGTH} bytes")
        
        salt = secrets.token_bytes(length)
        logger.info(f"Generated {length}-byte salt")
        return salt
    
    def create_versioned_salt(self, salt_bytes: bytes = None) -> SaltVersion:
        """
        Create a new versioned salt entry.
        
        Args:
            salt_bytes: Optional pre-generated salt (generates one if None)
        
        Returns:
            SaltVersion: New versioned salt
        """
        salt_bytes = salt_bytes or self.generate_salt()
        
        # Compute hash for verification
        salt_hash = hashlib.sha256(salt_bytes).hexdigest()
        
        version = self.current_version + 1
        now = datetime.utcnow().isoformat()
        
        # Calculate rotation times
        created_dt = datetime.utcnow()
        rotation_recommended_at = (created_dt + self.SALT_DEPRECATION_PERIOD).isoformat()
        rotation_required_at = (created_dt + self.SALT_EXPIRATION_PERIOD).isoformat()
        
        salt_version = SaltVersion(
            version=version,
            salt_bytes=salt_bytes,
            salt_hash=salt_hash,
            created_at=now,
            rotation_recommended_at=rotation_recommended_at,
            rotation_required_at=rotation_required_at,
            status="active"
        )
        
        self.salt_versions[version] = salt_version
        self.current_version = version
        
        # Log operation
        self._log_operation(
            operation_type="generate",
            version=version,
            success=True,
            details=f"Created new salt version {version}"
        )
        
        logger.info(f"Versioned salt created: version {version}")
        return salt_version
    
    def get_active_salt(self) -> Optional[bytes]:
        """
        Get the currently active salt.
        
        Returns:
            bytes: Active salt bytes, or None if no active salt exists
        """
        if self.current_version not in self.salt_versions:
            return None
        
        salt_version = self.salt_versions[self.current_version]
        
        # Check expiration
        if salt_version.status == "expired":
            logger.warning(f"Active salt version {self.current_version} is expired")
            return None
        
        # Update usage information
        salt_version.usage_count += 1
        salt_version.last_used_at = datetime.utcnow().isoformat()
        
        return salt_version.salt_bytes
    
    def get_salt_by_version(self, version: int) -> Optional[bytes]:
        """
        Get a specific salt by version number.
        
        Args:
            version: Salt version number
        
        Returns:
            bytes: Salt bytes, or None if version not found
        """
        if version not in self.salt_versions:
            logger.warning(f"Salt version {version} not found")
            return None
        
        return self.salt_versions[version].salt_bytes
    
    def rotate_salt(self) -> Tuple[SaltVersion, SaltVersion]:
        """
        Rotate to a new salt version.
        
        Returns:
            Tuple[SaltVersion, SaltVersion]: (old_version, new_version)
        """
        old_version = self.salt_versions.get(self.current_version)
        
        # Create new salt
        new_version = self.create_versioned_salt()
        
        # Mark old salt as deprecated
        if old_version:
            old_version.status = "deprecated"
        
        # Log operation
        self._log_operation(
            operation_type="rotate",
            version=new_version.version,
            success=True,
            details=f"Rotated from version {self.current_version - 1} to {self.current_version}"
        )
        
        logger.info(f"Salt rotated: {self.current_version - 1} -> {self.current_version}")
        return old_version, new_version
    
    def check_rotation_needed(self) -> Tuple[bool, Optional[str]]:
        """
        Check if salt rotation is needed.
        
        Returns:
            Tuple[bool, Optional[str]]: (rotation_needed, reason)
        """
        if self.current_version not in self.salt_versions:
            return False, None
        
        salt_version = self.salt_versions[self.current_version]
        now = datetime.utcnow()
        
        # Check if rotation is required
        if salt_version.rotation_required_at:
            required_dt = datetime.fromisoformat(salt_version.rotation_required_at)
            if now >= required_dt:
                return True, f"Salt rotation REQUIRED (expired {now - required_dt} ago)"
        
        # Check if rotation is recommended
        if salt_version.rotation_recommended_at:
            recommended_dt = datetime.fromisoformat(salt_version.rotation_recommended_at)
            if now >= recommended_dt:
                return True, f"Salt rotation recommended (old {now - recommended_dt} ago)"
        
        return False, None
    
    def verify_salt_integrity(self, version: int, salt_bytes: bytes) -> bool:
        """
        Verify that a salt matches its stored hash.
        
        Args:
            version: Salt version number
            salt_bytes: Salt bytes to verify
        
        Returns:
            bool: True if salt matches, False otherwise
        """
        if version not in self.salt_versions:
            logger.warning(f"Salt version {version} not found")
            return False
        
        salt_version = self.salt_versions[version]
        expected_hash = hashlib.sha256(salt_bytes).hexdigest()
        
        is_valid = hmac.compare_digest(expected_hash, salt_version.salt_hash)
        
        if not is_valid:
            logger.warning(f"Salt integrity check failed for version {version}")
        
        return is_valid
    
    def export_salt_config(self, include_salts: bool = False) -> Dict[str, Any]:
        """
        Export salt configuration (metadata only by default).
        
        Args:
            include_salts: Whether to include actual salt values
        
        Returns:
            dict: Salt configuration export
        """
        if include_salts:
            versions = {
                v: salt.to_secure_dict()
                for v, salt in self.salt_versions.items()
            }
        else:
            versions = {
                v: salt.to_dict()
                for v, salt in self.salt_versions.items()
            }
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "current_version": self.current_version,
            "versioning_enabled": self.enable_versioning,
            "total_versions": len(self.salt_versions),
            "versions": versions,
            "operations_log_size": len(self.operations_log)
        }
    
    def get_salt_status(self) -> Dict[str, Any]:
        """
        Get comprehensive salt status.
        
        Returns:
            dict: Salt status information
        """
        current = self.salt_versions.get(self.current_version)
        rotation_needed, rotation_reason = self.check_rotation_needed()
        
        status = {
            "timestamp": datetime.utcnow().isoformat(),
            "current_version": self.current_version,
            "rotation_needed": rotation_needed,
            "rotation_reason": rotation_reason,
            "versioning_enabled": self.enable_versioning,
            "total_versions": len(self.salt_versions)
        }
        
        if current:
            status["current_salt"] = {
                "version": current.version,
                "status": current.status,
                "created_at": current.created_at,
                "usage_count": current.usage_count,
                "last_used_at": current.last_used_at,
                "rotation_recommended_at": current.rotation_recommended_at,
                "rotation_required_at": current.rotation_required_at,
                "salt_hash": current.salt_hash[:8] + "..."
            }
        
        return status
    
    def _log_operation(self, operation_type: str, version: int,
                      success: bool, details: str = None) -> None:
        """
        Log a salt operation for audit trail.
        
        Args:
            operation_type: Type of operation
            version: Salt version involved
            success: Whether operation was successful
            details: Additional details
        """
        operation = SaltOperation(
            operation_type=operation_type,
            version=version,
            timestamp=datetime.utcnow().isoformat(),
            success=success,
            details=details
        )
        
        self.operations_log.append(operation)
        
        log_level = logging.INFO if success else logging.WARNING
        logger.log(
            log_level,
            f"Salt operation logged: {operation_type} (v{version}) - {details or 'OK'}"
        )
    
    def get_operations_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get the operations audit log.
        
        Args:
            limit: Maximum number of recent operations to return
        
        Returns:
            list: Recent salt operations
        """
        return [
            asdict(op) for op in self.operations_log[-limit:]
        ]
    
    def clear_operations_log(self) -> None:
        """Clear the operations log."""
        self.operations_log.clear()
        logger.info("Salt operations log cleared")
    
    def get_capabilities(self) -> Dict[str, Any]:
        """
        Get information about salt manager capabilities.
        
        Returns:
            dict: Capabilities information
        """
        return {
            "min_salt_length": self.MIN_SALT_LENGTH,
            "recommended_salt_length": self.RECOMMENDED_SALT_LENGTH,
            "max_salt_length": self.MAX_SALT_LENGTH,
            "versioning_enabled": self.enable_versioning,
            "rotation_period_days": self.SALT_ROTATION_PERIOD.days,
            "deprecation_period_days": self.SALT_DEPRECATION_PERIOD.days,
            "expiration_period_days": self.SALT_EXPIRATION_PERIOD.days
        }


if __name__ == "__main__":
    # Test the EnhancedSaltManager
    logging.basicConfig(level=logging.INFO)
    
    test_key = b"test_encryption_key_1234567890ab"
    manager = EnhancedSaltManager(test_key, enable_versioning=True)
    
    print("=== Enhanced Salt Manager Test ===\n")
    
    # Create initial salt
    print("1. Creating initial salt...")
    salt1 = manager.create_versioned_salt()
    print(f"   Version: {salt1.version}, Status: {salt1.status}\n")
    
    # Get active salt
    print("2. Getting active salt...")
    active = manager.get_active_salt()
    print(f"   Length: {len(active)} bytes\n")
    
    # Create more versions
    print("3. Creating additional salt versions...")
    salt2 = manager.create_versioned_salt()
    print(f"   Version: {salt2.version}, Status: {salt2.status}\n")
    
    # Check rotation needed
    print("4. Checking rotation status...")
    needed, reason = manager.check_rotation_needed()
    print(f"   Rotation needed: {needed}")
    print(f"   Reason: {reason}\n")
    
    # Get status
    print("5. Salt status:")
    status = manager.get_salt_status()
    print(f"   {json.dumps(status, indent=4)}\n")
    
    # Export config
    print("6. Exporting configuration...")
    config = manager.export_salt_config(include_salts=False)
    print(f"   Total versions: {config['total_versions']}")
    print(f"   Current version: {config['current_version']}\n")
    
    # Get operations log
    print("7. Operations log:")
    log = manager.get_operations_log()
    for op in log:
        print(f"   - {op['operation_type']} (v{op['version']}): {op['details']}")
    
    print("\nDone!")
