import time
import logging
from datetime import datetime, timedelta
from cryptography.exceptions import InvalidTag
import secrets
import base64
from pathlib import Path
import os
import json
import hmac
import hashlib
import platform
from machine_id_utils import generate_machine_id
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

class MachineKeyCryptoManager:
    """Handles encryption and decryption using a machine-specific key."""
    def __init__(self):
        self._encryption_key = self._get_machine_key()

    def _get_machine_key(self) -> bytes:
        """Derives a stable 32-byte encryption key from the machine ID."""
        machine_id = generate_machine_id()
        # Use a salt to ensure this key is unique to this purpose
        salted_id = f"lockout-crypto-key-{machine_id}"
        return hashlib.sha256(salted_id.encode()).digest()

    def encrypt(self, plaintext: str) -> str:
        """Encrypts data using AES-GCM and returns a base64-encoded string."""
        iv = os.urandom(12)  # GCM recommended nonce size
        cipher = Cipher(algorithms.AES(self._encryption_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        # Combine iv, tag, and ciphertext for storage
        encrypted_payload = iv + encryptor.tag + ciphertext
        return base64.b64encode(encrypted_payload).decode('utf-8')

    def decrypt(self, b64_ciphertext: str) -> str:
        """Decrypts a base64-encoded AES-GCM payload."""
        try:
            encrypted_payload = base64.b64decode(b64_ciphertext)
            iv = encrypted_payload[:12]
            tag = encrypted_payload[12:28]
            ciphertext = encrypted_payload[28:]
            
            cipher = Cipher(algorithms.AES(self._encryption_key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
            return decrypted_bytes.decode('utf-8')
        except (InvalidTag, ValueError, IndexError) as e:
            logger.warning(f"Decryption failed, possibly due to tampering or corruption: {e}")
            raise ValueError("Decryption failed") from e

class LockoutStateManager:
    """
    Manages the saving and loading of encrypted lockout state to multiple 
    redundant locations to prevent easy tampering or deletion.
    """
    def __init__(self):
        self._crypto = MachineKeyCryptoManager()
        self._storage_paths = self._get_storage_paths()

    def _get_storage_paths(self) -> list:
        """Defines multiple, less obvious storage locations for the state."""
        paths = []
        home = Path.home()
        
        paths.append('auth_state.json')

        if platform.system() == "Windows":
            app_data = os.environ.get('APPDATA')
            if app_data:
                paths.append(os.path.join(app_data, 'SecVault', 'status.dat'))
            temp_dir = os.environ.get('TEMP', 'C:\\Temp')
            paths.append(os.path.join(temp_dir, 'sec_auth_cache.dat'))
        else:
            paths.append(os.path.join(home, '.config', 'secvault_status.conf'))
            paths.append('/var/tmp/sec_auth_cache.dat')
            paths.append(os.path.join(home, '.auth_status.local'))

        return paths

    def load_state(self) -> dict:
        """
        Loads the encrypted lockout state from all locations, decrypts them, 
        and returns the most recent, valid state.
        """
        valid_states = []
        
        # Load from file paths
        for path in self._storage_paths:
            if not os.path.exists(path):
                continue
            try:
                with open(path, 'r') as f:
                    encrypted_data = f.read()
                decrypted_str = self._crypto.decrypt(encrypted_data)
                valid_states.append(json.loads(decrypted_str))
            except (ValueError, json.JSONDecodeError, OSError):
                continue
        
        # Load from Windows Registry
        if platform.system() == "Windows":
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\SecVault", 0, winreg.KEY_READ)
                encrypted_data, _ = winreg.QueryValueEx(key, "AuthState")
                decrypted_str = self._crypto.decrypt(encrypted_data)
                valid_states.append(json.loads(decrypted_str))
                winreg.CloseKey(key)
            except (ValueError, FileNotFoundError, OSError, json.JSONDecodeError):
                pass
        
        if not valid_states:
            return {}
        
        return max(valid_states, key=lambda s: s.get('guardian_lockout_end_time') or '')

    def save_state(self, state: dict):
        """Encrypts and saves the lockout state to all defined locations."""
        try:
            state_str = json.dumps(state)
            encrypted_data = self._crypto.encrypt(state_str)
            
            # Save to file paths
            for path in self._storage_paths:
                try:
                    dir_path = os.path.dirname(path)
                    if dir_path:
                        os.makedirs(dir_path, exist_ok=True)
                    with open(path, 'w') as f:
                        f.write(encrypted_data)
                except OSError as e:
                    logger.error(f"Failed to save state to {path}: {e}")

            # Save to Windows Registry
            if platform.system() == "Windows":
                try:
                    import winreg
                    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\SecVault")
                    winreg.SetValueEx(key, "AuthState", 0, winreg.REG_SZ, encrypted_data)
                    winreg.CloseKey(key)
                except OSError as e:
                    logger.error(f"Failed to save state to Windows Registry: {e}")
        except Exception as e:
            logger.error(f"Failed to prepare encrypted state for saving: {e}")

# Try to import pyotp for TOTP functionality
try:
    import pyotp
    PYOTP_AVAILABLE = True
except ImportError:
    PYOTP_AVAILABLE = False
    logger.warning("pyotp not available. 2FA functionality will be disabled. Install with: pip install pyotp qrcode[pil]")

# Try to import qrcode and PIL for QR code + image composition
try:
    import qrcode
    from qrcode.image.pil import PilImage as QRPilImage
    QRCODE_AVAILABLE = True
except Exception:
    qrcode = None
    QRPilImage = None
    QRCODE_AVAILABLE = False
    logger.info("qrcode library not available. QR code image generation will be disabled. Install with: pip install qrcode[pil]")

try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    Image = None
    PIL_AVAILABLE = False
    logger.info("Pillow (PIL) not available. Image composition will be disabled. Install with: pip install pillow")

class AuthGuardian:
    """
    Manages authentication security, including brute-force protection and lockouts.
    """
    # Constants for master password protection
    MAX_ATTEMPTS_BEFORE_LOCKOUT = 3
    INITIAL_LOCKOUT_MINUTES = 60
    SUBSEQUENT_LOCKOUT_INCREMENT_MINUTES = 30
    
    # Constants for 2FA protection
    MAX_TFA_ATTEMPTS_BEFORE_LOCKOUT = 5
    TFA_LOCKOUT_MINUTES = 15

    def __init__(self, settings_manager):
        """
        Initializes the AuthGuardian.

        Args:
            settings_manager: An object (like SecureFileManager) that can read/write settings.
        """
        self._settings_manager = settings_manager
        self.lockout_manager = LockoutStateManager()
        
        # Try to read settings, but only if encryption key is available
        # If no encryption key, start with empty dict and load after authentication
        if self._settings_manager and hasattr(self._settings_manager, 'encryption_key') and self._settings_manager.encryption_key:
            raw_settings = self._settings_manager.read_settings() or {}
            logger.info(f"AuthGuardian init: Settings loaded with encryption key. Keys: {list(raw_settings.keys())}")
        else:
            raw_settings = {}
            logger.info("AuthGuardian init: No encryption key available, starting with empty settings. Will reload after authentication.")
        
        # Load settings (2FA secret is now allowed)
        self._settings = raw_settings.copy()
        
        # Load master password state from the robust lockout manager
        lockout_state = self.lockout_manager.load_state()
        self.failed_attempts = lockout_state.get('guardian_failed_attempts', 0)
        self.consecutive_lockouts = lockout_state.get('guardian_consecutive_lockouts', 0)
        lockout_end_iso = lockout_state.get('guardian_lockout_end_time')
        self.lockout_end_time = datetime.fromisoformat(lockout_end_iso) if lockout_end_iso else None
        
        # Load 2FA state from encrypted settings
        self.tfa_failed_attempts = self._settings.get('guardian_tfa_failed_attempts', 0)
        self.consecutive_tfa_lockouts = self._settings.get('guardian_consecutive_tfa_lockouts', 0)
        tfa_lockout_end_iso = self._settings.get('guardian_tfa_lockout_end_time')
        self.tfa_lockout_end_time = datetime.fromisoformat(tfa_lockout_end_iso) if tfa_lockout_end_iso else None

        # Don't save state during initialization - encryption key might not be available yet
        # This prevents overwriting settings with empty dict when encryption key isn't set
        self._validate_state(save_state=False)

    def get_settings(self):
        """Returns a copy of the current settings."""
        return self._settings.copy()

    def update_setting(self, key: str, value):
        """
        Updates a specific setting and immediately persists the change.

        Args:
            key (str): The key of the setting to update.
            value: The new value for the setting.
        
        Returns:
            bool: True if the setting was successfully saved, False otherwise.
        """
        logger.info(f"Updating setting '{key}' and persisting changes.")
        self._settings[key] = value
        return self._save_state()

    def _validate_state(self, save_state=True):
        """Sanity check and cleanup of the loaded state."""
        if self.is_locked_out():
            if datetime.now() >= self.lockout_end_time:
                logger.info("Master password lockout period has expired. Resetting state.")
                self._reset_lockout()
        
        if self.is_tfa_locked_out():
            if datetime.now() >= self.tfa_lockout_end_time:
                logger.info("2FA lockout period has expired. Resetting state.")
                self._reset_tfa_lockout()

        self.failed_attempts = max(0, self.failed_attempts)
        self.consecutive_lockouts = max(0, self.consecutive_lockouts)
        self.tfa_failed_attempts = max(0, self.tfa_failed_attempts)
        self.consecutive_tfa_lockouts = max(0, self.consecutive_tfa_lockouts)
        
        if save_state:
            self._save_lockout_state()
            if self._settings_manager.encryption_key:
                self._save_state()

    def _save_lockout_state(self):
        """Saves the unencrypted lockout state using the robust manager."""
        state = {
            'guardian_failed_attempts': self.failed_attempts,
            'guardian_consecutive_lockouts': self.consecutive_lockouts,
            'guardian_lockout_end_time': self.lockout_end_time.isoformat() if self.lockout_end_time else None,
        }
        self.lockout_manager.save_state(state)

    def _save_state(self):
        """
        Saves the ENCRYPTED state (like 2FA settings) back to the settings file.
        This no longer saves the master password lockout state.
        """
        if not self._settings_manager.encryption_key:
            logger.warning("Cannot save encrypted state - encryption key is not available.")
            return False
        
        try:
            existing_settings = self._settings_manager.read_settings() or {}
        except Exception as e:
            logger.error(f"Could not load existing settings before save: {e}")
            return False
        
        settings_to_save = {**existing_settings, **self._settings}
        
        tfa_keys_to_remove = {'tfa_secret', 'tfa_enabled_at', 'tfa_backup_codes'}
        for key in tfa_keys_to_remove:
            if key not in self._settings and key in settings_to_save:
                del settings_to_save[key]
        
        settings_to_save['guardian_tfa_failed_attempts'] = self.tfa_failed_attempts
        settings_to_save['guardian_consecutive_tfa_lockouts'] = self.consecutive_tfa_lockouts
        settings_to_save['guardian_tfa_lockout_end_time'] = self.tfa_lockout_end_time.isoformat() if self.tfa_lockout_end_time else None
        
        try:
            success = self._settings_manager.write_settings(settings_to_save)
            if not success:
                logger.error("Failed to save encrypted guardian state.")
                return False
            logger.info("Successfully saved encrypted settings.")
            return True
        except Exception as e:
            logger.error(f"An unexpected error occurred while saving encrypted state: {e}")
            return False

    def record_login_attempt(self, success: bool):
        """
        Records the result of a master password login attempt and updates the security state.
        """
        if success:
            logger.info("Successful master password login recorded. Resetting lockout state.")
            self.failed_attempts = 0
            self.consecutive_lockouts = 0
            self.lockout_end_time = None
            self._save_lockout_state()
            self._reset_tfa_lockout()
        else:
            self.failed_attempts += 1
            logger.warning(f"Failed master password attempt #{self.failed_attempts} recorded.")
            
            if self.failed_attempts >= self.MAX_ATTEMPTS_BEFORE_LOCKOUT:
                self.consecutive_lockouts += 1
                
                if self.consecutive_lockouts == 1:
                    lockout_minutes = self.INITIAL_LOCKOUT_MINUTES
                else:
                    lockout_minutes = self.INITIAL_LOCKOUT_MINUTES + (self.consecutive_lockouts - 1) * self.SUBSEQUENT_LOCKOUT_INCREMENT_MINUTES
                
                self.lockout_end_time = datetime.now() + timedelta(minutes=lockout_minutes)
                logger.warning(f"Max master password attempts reached. Account locked for {lockout_minutes} minutes.")
            
            self._save_lockout_state()

    def is_locked_out(self) -> bool:
        """
        Checks if the account is currently in a hard lockout state.
        """
        if not self.lockout_end_time:
            return False
        
        if datetime.now() < self.lockout_end_time:
            return True
        else:
            self._reset_lockout()
            return False

    def get_remaining_lockout_time(self) -> int:
        """
        Gets the remaining lockout time in seconds.
        """
        if not self.is_locked_out():
            return 0
        
        remaining = self.lockout_end_time - datetime.now()
        return max(0, int(remaining.total_seconds()))

    def _reset_lockout(self):
        """Resets the state after a lockout expires."""
        self.lockout_end_time = None
        self.failed_attempts = 0
        self._save_lockout_state()
    
    def is_tfa_enabled(self) -> bool:
        """Check if 2FA is enabled for this account."""
        if not PYOTP_AVAILABLE:
            return False
        return 'tfa_secret' in self._settings and self._settings.get('tfa_secret') is not None
    
    def generate_tfa_secret(self) -> str:
        """Generate a new TOTP secret for 2FA setup."""
        if not PYOTP_AVAILABLE:
            raise ValueError("pyotp library is not available. Please install it: pip install pyotp")
        return pyotp.random_base32()
    

    def _get_icon_data_uri(self, max_size: int = 32) -> str:
        """Convert the 2FA icon to a base64 data URI for use in the provisioning URI.
        
        This icon will appear in 2FA apps like Google Authenticator if space permits.
        The data URI format allows embedding the icon directly in the provisioning URI without
        requiring external URL hosting.
        
        Args:
            max_size: Maximum pixel size for the icon (smaller = smaller URI). Default 32x32.
        
        Returns:
            str: The base64 data URI for the icon, or empty string if icon cannot be loaded.
        """
        if not PIL_AVAILABLE:
            logger.debug("PIL not available. Cannot generate icon data URI for 2FA provisioning.")
            return ""
        
        # Primary icon path - 2fa_icon.png is now the default
        icon_path = "icons/2fa_icon.png"
        
        # Fallback icon paths if primary doesn't exist
        icon_fallbacks = [
            "icons/load.png",
            "icons/security.png",
            "icons/main.png",
        ]
        
        # Check if primary icon exists, otherwise try fallbacks
        if not Path(icon_path).exists():
            logger.debug(f"Primary 2FA icon not found at {icon_path}, trying fallbacks...")
            for fallback in icon_fallbacks:
                if Path(fallback).exists():
                    icon_path = fallback
                    logger.debug(f"Using fallback icon: {icon_path}")
                    break
            else:
                logger.debug("No suitable icon found for 2FA provisioning URI")
                return ""
        
        try:
            # Open and process the icon image
            img = Image.open(icon_path)
            
            # Convert to RGBA if necessary
            if img.mode != 'RGBA':
                img = img.convert('RGBA')
            
            # Resize to small size for minimal URI data
            icon_size = (max_size, max_size)
            img.thumbnail(icon_size, Image.LANCZOS)
            
            # Ensure it's exactly the right size (pad if needed)
            if img.size != icon_size:
                new_img = Image.new('RGBA', icon_size, (255, 255, 255, 0))
                offset = ((icon_size[0] - img.size[0]) // 2, (icon_size[1] - img.size[1]) // 2)
                new_img.paste(img, offset, img)
                img = new_img
            
            # Convert to PNG bytes in memory with aggressive optimization
            from io import BytesIO
            buffer = BytesIO()
            # Use optimize=True and reduce colors for even smaller files
            img.save(buffer, format='PNG', optimize=True)
            png_data = buffer.getvalue()
            
            # If icon is still too large (>1200 bytes), return empty to keep URI compact
            if len(png_data) > 1200:
                logger.debug(f"Icon data too large ({len(png_data)} bytes) - skipping to keep URI compact")
                return ""
            
            # Encode as base64 and create data URI
            b64_data = base64.b64encode(png_data).decode('ascii')
            data_uri = f"data:image/png;base64,{b64_data}"
            
            logger.debug(f"Generated optimized icon data URI from {icon_path} ({len(data_uri)} chars)")
            return data_uri
            
        except Exception as e:
            logger.debug(f"Failed to generate icon data URI for 2FA provisioning: {e}")
            return ""
         
    def get_tfa_provisioning_uri(self, account_name: str = None, issuer_name: str = None, secret: str = None) -> str:
        """Get the provisioning URI for the TOTP secret (for QR code generation).
        
        Uses "Vault" as the default issuer name which is more likely to be recognized
        by 2FA apps and display a vault/security icon instead of a generic icon.
        
        Args:
            account_name: Account identifier (email or username)
            issuer_name: Service name shown in 2FA app (defaults to "Vault")
            secret: TOTP secret (uses stored secret if not provided)
        
        Returns:
            str: The provisioning URI for QR code generation
        """
        if not PYOTP_AVAILABLE:
            raise ValueError("pyotp library is not available")
        
        totp_secret = secret if secret else self._settings.get('tfa_secret')
        if not totp_secret:
            raise ValueError("2FA is not enabled")

        totp = pyotp.TOTP(totp_secret)

        # Use provided account_name or default
        effective_account_name = account_name if account_name else "SecureVault Pro"
        
        # Use a recognizable issuer name that's likely in 2FA app databases
        # Common recognized names that trigger vault/security icons:
        # Best options: "Vault", "Bitwarden", "1Password", "LastPass" (if you want their icons)
        # Generic options: "Security", "Password Manager", "Authenticator"
        # 
        # For maximum recognition, use "Vault" - it's generic enough and commonly recognized
        effective_issuer_name = issuer_name if issuer_name else "Vault"

        # Generate the provisioning URI
        uri = totp.provisioning_uri(name=effective_account_name, issuer_name=effective_issuer_name)
        
        logger.debug(f"Generated provisioning URI for {effective_account_name} with issuer '{effective_issuer_name}'")
        return uri

    def generate_tfa_qr_with_logo(self, account_name: str = None, issuer_name: str = "SecureVault",
                                logo_path: str = None, qr_size: int = 400, logo_scale: float = 0.34,
                                secret: str = None):
        """Generate a QR code PIL Image for the current TOTP secret and overlay the 2FA icon.

        This is where we CAN control the icon - by overlaying it on the QR code itself.
        Users will see your custom icon on the QR code, which helps with brand recognition.

        Args:
            account_name: Optional account name to include in the provisioning URI.
            issuer_name: Issuer name for the provisioning URI.
            logo_path: Path to a logo image. If None, uses 2fa_icon.png as default.
            qr_size: Size in pixels for the generated QR (square).
            logo_scale: Fractional size of logo relative to QR (0.0 - 0.5 typical).
            secret: Optional secret (uses stored secret if not provided).

        Returns:
            PIL.Image: The composed image object ready for display or saving.

        Raises:
            ValueError: If required libraries or TOTP secret are missing.
        """
        if not PYOTP_AVAILABLE:
            raise ValueError("pyotp is required to generate TOTP provisioning URIs")
        if not QRCODE_AVAILABLE or not PIL_AVAILABLE:
            raise ValueError("qrcode and pillow are required to generate QR images with logos")
        
        totp_secret = secret if secret else self._settings.get('tfa_secret')
        if not totp_secret:
            raise ValueError("2FA secret is not available. Provide `secret` parameter or enable 2FA first.")

        effective_account_name = account_name if account_name else "SecureVault Pro"

        totp = pyotp.TOTP(totp_secret)
        uri = totp.provisioning_uri(name=effective_account_name, issuer_name=issuer_name)

        # Create QR code
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=4)
        qr.add_data(uri)
        qr.make(fit=True)
        qr_img = qr.make_image(image_factory=QRPilImage).convert('RGBA')
        
        # Determine logo path - DEFAULT TO 2fa_icon.png
        if not logo_path:
            # Try 2fa_icon.png first (our primary icon)
            icon_candidates = [
                'icons/2fa_icon.png',  # PRIMARY - Your custom 2FA icon
                'icons/load.png',
                'icons/security.png',
                'icons/mainlogo.png'
            ]
            
            found = None
            for candidate in icon_candidates:
                try:
                    if Path(candidate).exists():
                        found = candidate
                        logger.info(f"Using 2FA icon: {candidate}")
                        break
                except Exception:
                    continue
            logo_path = found

        # If no logo found, just return the QR image
        if not logo_path:
            logger.warning("No 2FA icon found, returning QR code without logo")
            return qr_img

        # Load and process logo image
        try:
            logo_img = Image.open(logo_path).convert('RGBA')
            logger.info(f"Successfully loaded 2FA icon from: {logo_path}")
        except Exception as e:
            logger.warning(f"Failed to open logo at {logo_path}: {e}")
            return qr_img

        # Make the logo square (centered) for better appearance
        lw, lh = logo_img.size
        if lw != lh:
            side = max(lw, lh)
            square = Image.new('RGBA', (side, side), (255, 255, 255, 0))
            paste_pos = ((side - lw) // 2, (side - lh) // 2)
            square.paste(logo_img, paste_pos, logo_img)
            logo_img = square

        # Calculate logo size and paste centered
        logo_max_size = int(qr_size * float(logo_scale))
        logo_w, logo_h = logo_img.size
        scale = min(logo_max_size / logo_w, logo_max_size / logo_h, 1.0)
        new_logo_size = (max(1, int(logo_w * scale)), max(1, int(logo_h * scale)))
        logo_img = logo_img.resize(new_logo_size, resample=Image.LANCZOS)

        # Create white background for the logo for better visibility
        padding = max(6, int(logo_max_size * 0.10))
        bg_size = (logo_img.size[0] + padding * 2, logo_img.size[1] + padding * 2)
        bg = Image.new('RGBA', bg_size, (255, 255, 255, 255))
        
        # Create rounded corners for the background
        mask = None
        try:
            from PIL import ImageDraw
            mask = Image.new('L', bg_size, 0)
            draw_mask = ImageDraw.Draw(mask)
            corner_radius = int(min(bg_size) * 0.12)
            draw_mask.rounded_rectangle([(0, 0), (bg_size[0]-1, bg_size[1]-1)], radius=corner_radius, fill=255)
        except Exception:
            mask = None

        # Compose images: QR base -> bg -> logo (centered)
        composed = Image.new('RGBA', (qr_size, qr_size), (255, 255, 255, 0))
        composed.paste(qr_img, (0, 0))

        # Position background centered
        bg_pos = ((qr_size - bg_size[0]) // 2, (qr_size - bg_size[1]) // 2)
        if mask:
            composed.paste(bg, bg_pos, mask)
        else:
            composed.paste(bg, bg_pos)

        # Position logo centered on top of background
        logo_pos = ((qr_size - logo_img.size[0]) // 2, (qr_size - logo_img.size[1]) // 2)
        try:
            composed.paste(logo_img, logo_pos, logo_img)
            logger.info("Successfully composed QR code with 2FA icon overlay")
        except Exception:
            composed.paste(logo_img, logo_pos)

        return composed
        
    def enable_tfa(self, secret: str) -> bool:
        """Enable 2FA with the given secret."""
        if not PYOTP_AVAILABLE:
            raise ValueError("pyotp library is not available. Please install it: pip install pyotp")
        if not secret or len(secret) < 16:
            raise ValueError("Invalid TOTP secret")
        self._settings['tfa_secret'] = secret
        self._settings['tfa_enabled_at'] = datetime.now().isoformat()
        # Reset 2FA failure state when enabling
        self.tfa_failed_attempts = 0
        self.consecutive_tfa_lockouts = 0
        self.tfa_lockout_end_time = None
        return self._save_state()
    
    def disable_tfa(self) -> bool:
        """Disable 2FA for this account."""
        if 'tfa_secret' in self._settings:
            del self._settings['tfa_secret']
        if 'tfa_enabled_at' in self._settings:
            del self._settings['tfa_enabled_at']
        if 'tfa_backup_codes' in self._settings:
            del self._settings['tfa_backup_codes']
        # Reset 2FA failure state
        self.tfa_failed_attempts = 0
        self.consecutive_tfa_lockouts = 0
        self.tfa_lockout_end_time = None
        return self._save_state()
    
    def verify_tfa_code(self, code: str) -> bool:
        """Verify a TOTP code."""
        if not PYOTP_AVAILABLE:
            return False
        if not self.is_tfa_enabled():
            return False
        if self.is_tfa_locked_out():
            logger.warning("2FA verification attempted while locked out")
            return False
        # Verify TOTP code
        try:
            totp = pyotp.TOTP(self._settings['tfa_secret'])
            # Allow a time window of ±1 time step (30 seconds) for clock skew
            is_valid = totp.verify(code, valid_window=1)
            if is_valid:
                self.tfa_failed_attempts = 0
                self.consecutive_tfa_lockouts = 0
                self._save_state()
                logger.info("2FA code verified successfully")
            else:
                self.record_tfa_attempt(success=False)
            return is_valid
        except Exception as e:
            logger.error(f"Error verifying 2FA code: {e}")
            self.record_tfa_attempt(success=False)
            return False
    
    def record_tfa_attempt(self, success: bool):
        """Record a 2FA verification attempt."""
        if success:
            logger.info("Successful 2FA attempt recorded. Resetting 2FA failure count.")
            self.tfa_failed_attempts = 0
            self.consecutive_tfa_lockouts = 0
        else:
            self.tfa_failed_attempts += 1
            logger.warning(f"Failed 2FA attempt #{self.tfa_failed_attempts} recorded.")
            
            if self.tfa_failed_attempts >= self.MAX_TFA_ATTEMPTS_BEFORE_LOCKOUT:
                self.consecutive_tfa_lockouts += 1
                lockout_duration = timedelta(minutes=self.TFA_LOCKOUT_MINUTES * self.consecutive_tfa_lockouts)
                self.tfa_lockout_end_time = datetime.now() + lockout_duration
                logger.warning(f"Max 2FA attempts reached. Locked for {lockout_duration.total_seconds() / 60} minutes.")
                self.tfa_failed_attempts = 0  # Reset attempts after lockout
        
        self._save_state()
    
    def is_tfa_locked_out(self) -> bool:
        """Check if 2FA is currently locked out."""
        if not self.tfa_lockout_end_time:
            return False
        
        if datetime.now() < self.tfa_lockout_end_time:
            return True
        else:
            self._reset_tfa_lockout()
            return False
    
    def get_remaining_tfa_lockout_time(self) -> int:
        """Get remaining 2FA lockout time in seconds."""
        if not self.is_tfa_locked_out():
            return 0
        
        remaining = self.tfa_lockout_end_time - datetime.now()
        return max(0, int(remaining.total_seconds()))
    
    def _reset_tfa_lockout(self):
        """Reset 2FA lockout state."""
        self.tfa_lockout_end_time = None
        self.tfa_failed_attempts = 0
        self.consecutive_tfa_lockouts = 0
        self._save_state()
    
    def reload_settings(self):
        """Reloads settings from the settings manager."""
        new_settings = self._settings_manager.read_settings() or {}
        logger.info(f"Reloading settings, read_settings returned: {list(new_settings.keys())}")
        logger.info(f"tfa_secret present in reloaded settings: {'tfa_secret' in new_settings}")
        logger.info(f"tfa_enabled_at present in reloaded settings: {'tfa_enabled_at' in new_settings}")
        
        # Clear settings and reload
        self._settings.clear()
        self._settings.update(new_settings)
        
        # Re-load master password state
        self.failed_attempts = self._settings.get('guardian_failed_attempts', 0)
        self.consecutive_lockouts = self._settings.get('guardian_consecutive_lockouts', 0)
        lockout_end_iso = self._settings.get('guardian_lockout_end_time')
        self.lockout_end_time = datetime.fromisoformat(lockout_end_iso) if lockout_end_iso else None
        
        # Re-load 2FA state
        self.tfa_failed_attempts = self._settings.get('guardian_tfa_failed_attempts', 0)
        self.consecutive_tfa_lockouts = self._settings.get('guardian_consecutive_tfa_lockouts', 0)
        tfa_lockout_end_iso = self._settings.get('guardian_tfa_lockout_end_time')
        self.tfa_lockout_end_time = datetime.fromisoformat(tfa_lockout_end_iso) if tfa_lockout_end_iso else None

        # After reloading settings, validate state but don't save (save only happens on explicit updates)
        # This prevents unnecessary saves that might cause issues
        self._validate_state(save_state=False)
        logger.info(f"After reload, _settings has: {list(self._settings.keys())}")
        logger.info(f"After reload, is_tfa_enabled(): {self.is_tfa_enabled()}")
