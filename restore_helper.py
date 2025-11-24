import os
import shutil
import tempfile
from datetime import datetime
import logging
import json
from backup_manager import BackupManager, BackupError

logger = logging.getLogger(__name__)

def restore_backup_into_vault(backup_path: str, backup_code: str, vault_dir: str,
                              master_password: str,
                              metadata_name="metadata.db", sensitive_name="sensitive.db",
                              salt_name="salt_file", integrity_name="integrity_file"):
    """
    Restore from backup_path using backup_code into vault_dir.
    
    CRITICAL: This function restores files AS-IS without re-encryption, because:
    - Backup files are encrypted with the backup's original salt
    - The salt file in the backup defines the correct key derivation context
    - Re-encrypting with a different salt would break the encrypted data
    - The master_password on restart will work with the restored salt file
    
    Returns dict with details about restored and backed-up files.
    """
    logger.info(f"Attempting to restore backup from {backup_path} into vault {vault_dir}")
    if not os.path.exists(backup_path):
        logger.error(f"Backup file not found: {backup_path}")
        raise FileNotFoundError(f"Backup file not found: {backup_path}")

    os.makedirs(vault_dir, exist_ok=True)
    tempdir = tempfile.mkdtemp(prefix="sv_restore_")
    logger.info(f"Created temporary directory for restore: {tempdir}")
    
    bm = BackupManager(
        metadata_db_path=os.path.join(vault_dir, metadata_name),
        sensitive_db_path=os.path.join(vault_dir, sensitive_name),
        salt_path=os.path.join(vault_dir, salt_name),
        integrity_path=os.path.join(vault_dir, integrity_name),
        backups_dir=os.path.join(os.getcwd(), "backups")
    )

    try:
        restored_files = bm.restore_backup(backup_path, backup_code, restore_to_dir=tempdir)
        logger.info(f"Successfully restored {len(restored_files)} files to temporary directory.")
    except BackupError as e:
        logger.error(f"Failed to restore backup: {e}", exc_info=True)
        shutil.rmtree(tempdir, ignore_errors=True)
        raise

    # CRITICAL: Do NOT re-encrypt the backup files
    # The restored databases are already encrypted with the backup's original salt
    # If we re-encrypt them, they become unreadable with the restored salt file
    logger.info("Skipping re-encryption of backup files.")
    logger.info("The backup files are already properly encrypted with their original salt.")
    logger.info("The restored salt file will be used for key derivation on next login.")

    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    moved = []
    backups_created = []

    logger.info("Moving restored files into vault directory...")
    for f in restored_files:
        basename = os.path.basename(f)
        if basename == "backup_manifest.json":
            # Skip manifest file - it's just metadata
            logger.debug(f"Skipping manifest file: {basename}")
            continue

        dest = os.path.join(vault_dir, basename)
        if os.path.exists(dest):
            bak_name = f"{dest}.bak.{timestamp}"
            logger.info(f"Backing up existing file {dest} to {bak_name}")
            shutil.move(dest, bak_name)
            backups_created.append(bak_name)

        logger.info(f"Moving {f} to {dest}")
        shutil.move(f, dest)
        moved.append(dest)
    
    # IMPORTANT: Verify all critical files are in place
    critical_files = [
        os.path.join(vault_dir, metadata_name),
        os.path.join(vault_dir, sensitive_name),
        os.path.join(vault_dir, salt_name)
    ]
    
    for crit_file in critical_files:
        if not os.path.exists(crit_file):
            logger.error(f"CRITICAL: Required file missing after restore: {crit_file}")
            shutil.rmtree(tempdir, ignore_errors=True)
            raise FileNotFoundError(f"Critical file missing after restore: {crit_file}")
        logger.info(f"✓ Verified file exists: {os.path.basename(crit_file)}")

    # cleanup temporary directory
    try:
        logger.info(f"Cleaning up temporary directory: {tempdir}")
        shutil.rmtree(tempdir)
    except Exception as e:
        logger.warning(f"Failed to clean up temporary directory: {tempdir}: {e}")
        pass
    
    logger.info(f"Restore complete. Moved {len(moved)} files, created {len(backups_created)} backups.")
    logger.info("IMPORTANT: The application must be restarted for the restored data to be loaded.")
    logger.info("On next login, use the same master password with the restored salt file.")
    
    return {"restored_to": moved, "backups_created": backups_created}