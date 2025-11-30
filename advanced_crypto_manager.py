"""
AdvancedCryptoManager: Enterprise-grade encryption and key derivation
Implements industry-standard cryptographic algorithms with multiple options:
- AES-256-GCM for authenticated encryption
- PBKDF2, Argon2id for key derivation
- HMAC-SHA256 for integrity verification
- Secure random number generation
"""

import os
import logging
import base64
import json
import hashlib
import hmac
from datetime import datetime
from enum import Enum
from typing import Tuple, Optional, Dict, Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

logger = logging.getLogger(__name__)

# Try to import Argon2 for advanced password hashing
try:
    from argon2 import PasswordHasher as Argon2Hasher
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
    logger.warning("Argon2 not available. Install with: pip install argon2-cffi")

# Try to import bcrypt
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    logger.warning("bcrypt not available. Install with: pip install bcrypt")


class KeyDerivationMethod(Enum):
    """Supported key derivation methods."""
    PBKDF2_SHA256 = "pbkdf2_sha256"
    ARGON2ID = "argon2id"
    BCRYPT = "bcrypt"


class PasswordHashingMethod(Enum):
    """Supported password hashing methods."""
    PBKDF2_SHA256 = "pbkdf2_sha256"
    ARGON2ID = "argon2id"
    BCRYPT = "bcrypt"
    SCRYPT = "scrypt"


class AdvancedCryptoManager:
    """
    Advanced cryptographic operations with multiple algorithm options.
    Provides AES-256-GCM encryption, PBKDF2/Argon2 key derivation,
    and HMAC-based integrity verification.
    """
    
    # AES-256 configuration
    KEY_SIZE = 32  # 256 bits for AES-256
    IV_SIZE = 16   # 128 bits for GCM
    TAG_SIZE = 16  # 128 bits for authentication tag
    
    # PBKDF2 configuration
    PBKDF2_ITERATIONS = 480000  # NIST recommendation for 2024
    PBKDF2_HASH = hashes.SHA256()
    
    # Argon2 configuration (only if available)
    ARGON2_TIME_COST = 3  # Number of iterations
    ARGON2_MEMORY_COST = 65536  # Memory in KiB
    ARGON2_PARALLELISM = 4  # Number of parallel threads
    
    # Bcrypt configuration (only if available)
    BCRYPT_ROUNDS = 12
    
    def __init__(self, backend=None):
        """
        Initialize the AdvancedCryptoManager.
        
        Args:
            backend: Optional cryptography backend (defaults to system default)
        """
        self.backend = backend or default_backend()
        self.default_kdf_method = self._select_best_kdf_method()
        self.default_password_hash_method = self._select_best_password_hash_method()
        
        logger.info(f"AdvancedCryptoManager initialized")
        logger.info(f"Best KDF method: {self.default_kdf_method.value}")
        logger.info(f"Best password hash method: {self.default_password_hash_method.value}")
    
    def _select_best_kdf_method(self) -> KeyDerivationMethod:
        """Select the best available key derivation method."""
        if ARGON2_AVAILABLE:
            return KeyDerivationMethod.ARGON2ID
        else:
            return KeyDerivationMethod.PBKDF2_SHA256
    
    def _select_best_password_hash_method(self) -> PasswordHashingMethod:
        """Select the best available password hashing method."""
        if ARGON2_AVAILABLE:
            return PasswordHashingMethod.ARGON2ID
        elif BCRYPT_AVAILABLE:
            return PasswordHashingMethod.BCRYPT
        else:
            return PasswordHashingMethod.PBKDF2_SHA256
    
    def generate_salt(self, length: int = 32) -> bytes:
        """
        Generate a cryptographically secure random salt.
        
        Args:
            length: Length of salt in bytes (default 32 for 256 bits)
        
        Returns:
            bytes: Random salt
        """
        salt = os.urandom(length)
        logger.debug(f"Generated {length}-byte salt")
        return salt
    
    def derive_key_pbkdf2(self, password: str, salt: bytes, 
                         iterations: int = None, key_length: int = None) -> bytes:
        """
        Derive a key from password using PBKDF2-SHA256.
        
        Args:
            password: Master password
            salt: Random salt
            iterations: Number of iterations (default: NIST recommendation)
            key_length: Length of derived key in bytes (default: 32 for AES-256)
        
        Returns:
            bytes: Derived key
        """
        iterations = iterations or self.PBKDF2_ITERATIONS
        key_length = key_length or self.KEY_SIZE
        
        kdf = PBKDF2HMAC(
            algorithm=self.PBKDF2_HASH,
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        
        key = kdf.derive(password.encode('utf-8'))
        logger.info(f"PBKDF2 key derived with {iterations} iterations")
        return key
    
    def derive_key_argon2(self, password: str, salt: bytes, 
                         key_length: int = None) -> bytes:
        """
        Derive a key from password using Argon2id.
        
        Args:
            password: Master password
            salt: Random salt (will be used directly)
            key_length: Length of derived key in bytes (default: 32)
        
        Returns:
            bytes: Derived key
        
        Raises:
            ValueError: If Argon2 is not available
        """
        if not ARGON2_AVAILABLE:
            raise ValueError("Argon2 is not available. Install argon2-cffi to use Argon2 key derivation.")
        
        key_length = key_length or self.KEY_SIZE
        
        try:
            from argon2 import low_level
            
            # Use Argon2id algorithm
            key = low_level.hash_secret(
                password.encode('utf-8'),
                salt,
                time_cost=self.ARGON2_TIME_COST,
                memory_cost=self.ARGON2_MEMORY_COST,
                parallelism=self.ARGON2_PARALLELISM,
                hash_len=key_length,
                type=low_level.Type.ID
            )
            
            logger.info(f"Argon2id key derived (time={self.ARGON2_TIME_COST}, memory={self.ARGON2_MEMORY_COST}KiB)")
            return key
        except Exception as e:
            logger.error(f"Argon2 key derivation failed: {e}")
            raise
    
    def derive_key(self, password: str, salt: bytes, 
                   method: KeyDerivationMethod = None,
                   **kwargs) -> bytes:
        """
        Derive a key using the specified method (or best available).
        
        Args:
            password: Master password
            salt: Random salt
            method: Key derivation method (default: best available)
            **kwargs: Additional arguments for specific methods
        
        Returns:
            bytes: Derived key
        """
        method = method or self.default_kdf_method
        
        if method == KeyDerivationMethod.ARGON2ID:
            return self.derive_key_argon2(password, salt, **kwargs)
        elif method == KeyDerivationMethod.PBKDF2_SHA256:
            return self.derive_key_pbkdf2(password, salt, **kwargs)
        else:
            raise ValueError(f"Unsupported key derivation method: {method}")
    
    def encrypt_aes256_gcm(self, plaintext: str, key: bytes) -> bytes:
        """
        Encrypt data using AES-256-GCM (authenticated encryption).
        
        Args:
            plaintext: Data to encrypt
            key: Encryption key (must be 32 bytes for AES-256)
        
        Returns:
            bytes: IV + Tag + Ciphertext (ready for storage)
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes for AES-256")
        
        iv = os.urandom(self.IV_SIZE)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        tag = encryptor.tag
        
        # Return: IV (16) + Tag (16) + Ciphertext
        encrypted = iv + tag + ciphertext
        logger.debug(f"AES-256-GCM encryption completed: {len(ciphertext)} bytes")
        return encrypted
    
    def decrypt_aes256_gcm(self, encrypted: bytes, key: bytes) -> str:
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            encrypted: Encrypted data (IV + Tag + Ciphertext)
            key: Encryption key (must be 32 bytes for AES-256)
        
        Returns:
            str: Decrypted plaintext
        
        Raises:
            InvalidTag: If authentication tag verification fails
            ValueError: If encrypted data is malformed
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes for AES-256")
        
        if len(encrypted) < self.IV_SIZE + self.TAG_SIZE:
            raise ValueError("Encrypted data is too short")
        
        # Extract components
        iv = encrypted[:self.IV_SIZE]
        tag = encrypted[self.IV_SIZE:self.IV_SIZE + self.TAG_SIZE]
        ciphertext = encrypted[self.IV_SIZE + self.TAG_SIZE:]
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            logger.debug(f"AES-256-GCM decryption completed")
            return plaintext.decode('utf-8')
        except InvalidTag:
            logger.error("AES-256-GCM: Authentication tag verification failed!")
            raise InvalidTag("Decryption failed - data may be tampered or key is incorrect")
    
    def hash_password_pbkdf2(self, password: str, salt: bytes = None,
                           iterations: int = None) -> Tuple[bytes, bytes]:
        """
        Hash a password using PBKDF2-SHA256.
        
        Args:
            password: Password to hash
            salt: Optional salt (generated if not provided)
            iterations: Number of iterations (default: NIST recommendation)
        
        Returns:
            Tuple[bytes, bytes]: (hash, salt)
        """
        salt = salt or self.generate_salt()
        iterations = iterations or self.PBKDF2_ITERATIONS
        
        kdf = PBKDF2HMAC(
            algorithm=self.PBKDF2_HASH,
            length=32,
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        
        hash_result = kdf.derive(password.encode('utf-8'))
        logger.info(f"PBKDF2 password hash created with {iterations} iterations")
        return hash_result, salt
    
    def verify_password_pbkdf2(self, password: str, hash_result: bytes, 
                              salt: bytes, iterations: int = None) -> bool:
        """
        Verify a PBKDF2 password hash.
        
        Args:
            password: Password to verify
            hash_result: Previously computed hash
            salt: Salt used in hashing
            iterations: Number of iterations used (default: NIST recommendation)
        
        Returns:
            bool: True if password matches, False otherwise
        """
        iterations = iterations or self.PBKDF2_ITERATIONS
        computed_hash, _ = self.hash_password_pbkdf2(password, salt, iterations)
        return hmac.compare_digest(computed_hash, hash_result)
    
    def hash_password_argon2(self, password: str) -> str:
        """
        Hash a password using Argon2id.
        
        Args:
            password: Password to hash
        
        Returns:
            str: Hash string in Argon2 format (includes salt and parameters)
        
        Raises:
            ValueError: If Argon2 is not available
        """
        if not ARGON2_AVAILABLE:
            raise ValueError("Argon2 is not available. Install argon2-cffi to use Argon2 password hashing.")
        
        try:
            hasher = Argon2Hasher(
                time_cost=self.ARGON2_TIME_COST,
                memory_cost=self.ARGON2_MEMORY_COST,
                parallelism=self.ARGON2_PARALLELISM,
                hash_len=16,
                type=1  # Argon2id
            )
            hash_result = hasher.hash(password)
            logger.info("Argon2id password hash created")
            return hash_result
        except Exception as e:
            logger.error(f"Argon2 password hashing failed: {e}")
            raise
    
    def verify_password_argon2(self, password: str, hash_result: str) -> bool:
        """
        Verify an Argon2 password hash.
        
        Args:
            password: Password to verify
            hash_result: Previously computed hash string
        
        Returns:
            bool: True if password matches, False otherwise
        """
        if not ARGON2_AVAILABLE:
            raise ValueError("Argon2 is not available")
        
        try:
            hasher = Argon2Hasher()
            hasher.verify(hash_result, password)
            return True
        except Exception:
            return False
    
    def hash_password_bcrypt(self, password: str, rounds: int = None) -> bytes:
        """
        Hash a password using bcrypt.
        
        Args:
            password: Password to hash
            rounds: Number of rounds (cost factor)
        
        Returns:
            bytes: Hash in bcrypt format
        
        Raises:
            ValueError: If bcrypt is not available
        """
        if not BCRYPT_AVAILABLE:
            raise ValueError("bcrypt is not available. Install with: pip install bcrypt")
        
        rounds = rounds or self.BCRYPT_ROUNDS
        salt = bcrypt.gensalt(rounds=rounds)
        hash_result = bcrypt.hashpw(password.encode('utf-8'), salt)
        logger.info(f"bcrypt password hash created with {rounds} rounds")
        return hash_result
    
    def verify_password_bcrypt(self, password: str, hash_result: bytes) -> bool:
        """
        Verify a bcrypt password hash.
        
        Args:
            password: Password to verify
            hash_result: Previously computed hash
        
        Returns:
            bool: True if password matches, False otherwise
        """
        if not BCRYPT_AVAILABLE:
            raise ValueError("bcrypt is not available")
        
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hash_result)
        except Exception as e:
            logger.error(f"bcrypt verification error: {e}")
            return False
    
    def hash_password(self, password: str, 
                     method: PasswordHashingMethod = None,
                     **kwargs) -> Dict[str, Any]:
        """
        Hash a password using the best available method.
        
        Args:
            password: Password to hash
            method: Hashing method (default: best available)
            **kwargs: Additional arguments for specific methods
        
        Returns:
            dict: Hash information including method, hash, and metadata
        """
        method = method or self.default_password_hash_method
        
        if method == PasswordHashingMethod.ARGON2ID:
            hash_result = self.hash_password_argon2(password, **kwargs)
            return {
                "method": "argon2id",
                "hash": hash_result,
                "timestamp": datetime.now().isoformat()
            }
        elif method == PasswordHashingMethod.BCRYPT:
            hash_result = self.hash_password_bcrypt(password, **kwargs)
            return {
                "method": "bcrypt",
                "hash": base64.b64encode(hash_result).decode('utf-8'),
                "timestamp": datetime.now().isoformat()
            }
        elif method == PasswordHashingMethod.PBKDF2_SHA256:
            hash_result, salt = self.hash_password_pbkdf2(password, **kwargs)
            return {
                "method": "pbkdf2_sha256",
                "hash": base64.b64encode(hash_result).decode('utf-8'),
                "salt": base64.b64encode(salt).decode('utf-8'),
                "timestamp": datetime.now().isoformat()
            }
        else:
            raise ValueError(f"Unsupported password hashing method: {method}")
    
    def verify_password(self, password: str, hash_info: Dict[str, Any]) -> bool:
        """
        Verify a password against hash information.
        
        Args:
            password: Password to verify
            hash_info: Hash information dict from hash_password()
        
        Returns:
            bool: True if password matches, False otherwise
        """
        method = hash_info.get("method")
        
        if method == "argon2id":
            return self.verify_password_argon2(password, hash_info["hash"])
        elif method == "bcrypt":
            hash_bytes = base64.b64decode(hash_info["hash"])
            return self.verify_password_bcrypt(password, hash_bytes)
        elif method == "pbkdf2_sha256":
            hash_bytes = base64.b64decode(hash_info["hash"])
            salt = base64.b64decode(hash_info["salt"])
            return self.verify_password_pbkdf2(password, hash_bytes, salt)
        else:
            logger.error(f"Unknown hash method: {method}")
            return False
    
    def generate_hmac_sha256(self, data: bytes, key: bytes) -> bytes:
        """
        Generate an HMAC-SHA256 signature.
        
        Args:
            data: Data to sign
            key: Key for HMAC
        
        Returns:
            bytes: HMAC signature
        """
        signature = hmac.new(key, data, hashlib.sha256).digest()
        logger.debug(f"HMAC-SHA256 signature generated")
        return signature
    
    def verify_hmac_sha256(self, data: bytes, signature: bytes, key: bytes) -> bool:
        """
        Verify an HMAC-SHA256 signature.
        
        Args:
            data: Data to verify
            signature: Expected signature
            key: Key for HMAC
        
        Returns:
            bool: True if signature is valid, False otherwise
        """
        expected_signature = self.generate_hmac_sha256(data, key)
        return hmac.compare_digest(expected_signature, signature)
    
    def get_capabilities(self) -> Dict[str, bool]:
        """
        Get information about available cryptographic capabilities.
        
        Returns:
            dict: Availability of different algorithms
        """
        return {
            "pbkdf2": True,
            "argon2id": ARGON2_AVAILABLE,
            "bcrypt": BCRYPT_AVAILABLE,
            "aes256_gcm": True,
            "hmac_sha256": True,
        }


# Create a singleton instance
_advanced_crypto_manager = None


def get_advanced_crypto_manager() -> AdvancedCryptoManager:
    """
    Get or create the global AdvancedCryptoManager instance.
    
    Returns:
        AdvancedCryptoManager: The global instance
    """
    global _advanced_crypto_manager
    if _advanced_crypto_manager is None:
        _advanced_crypto_manager = AdvancedCryptoManager()
    return _advanced_crypto_manager


if __name__ == "__main__":
    # Test the AdvancedCryptoManager
    logging.basicConfig(level=logging.INFO)
    
    manager = AdvancedCryptoManager()
    
    print("=== Capabilities ===")
    print(json.dumps(manager.get_capabilities(), indent=2))
    
    print("\n=== Key Derivation Test ===")
    password = "TestPassword123!@#"
    salt = manager.generate_salt()
    key = manager.derive_key(password, salt)
    print(f"Derived key length: {len(key)} bytes")
    
    print("\n=== Encryption/Decryption Test ===")
    plaintext = "This is a secret message!"
    encrypted = manager.encrypt_aes256_gcm(plaintext, key)
    decrypted = manager.decrypt_aes256_gcm(encrypted, key)
    print(f"Original: {plaintext}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {plaintext == decrypted}")
    
    print("\n=== Password Hashing Test ===")
    hash_info = manager.hash_password(password)
    print(f"Hash info: {hash_info}")
    verified = manager.verify_password(password, hash_info)
    print(f"Password verified: {verified}")
