import os
import shutil
import tempfile
from datetime import datetime
import logging
import json
from backup_manager import BackupManager, BackupError
from secure_file_manager import SecureFileManager

logger = logging.getLogger(__name__)

def restore_backup_into_vault(backup_path: str, backup_code: str, vault_dir: str,
                              master_password: str,
                              metadata_name="metadata.db", sensitive_name="sensitive.db",
                              salt_name="salt_file", integrity_name="integrity_file"):
    """
    Restore from backup_path using backup_code into vault_dir.
    - Restores to a temporary directory first.
    - Backs up any existing target files in vault_dir by renaming them with .bak.TIMESTAMP
    - Moves restored files into vault_dir.
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

    if master_password:
        logger.info("Master password provided, proceeding with re-encryption of restored files.")
        try:
            sfm = SecureFileManager(secure_dir=tempdir)
            sfm.initialize_encryption(master_password)
            settings_path_in_temp = os.path.join(tempdir, "settings.json")
            if os.path.exists(settings_path_in_temp):
                logger.info("Found settings.json in restored files, re-encrypting it now.")
                with open(settings_path_in_temp, "r") as f:
                    settings_data = json.load(f)
                if not sfm.write_settings(settings_data):
                    raise Exception("Failed to write encrypted settings.")
                logger.info("Successfully re-encrypted settings.json.")
            else:
                logger.info("No settings.json found in the backup, skipping re-encryption for it.")
            logger.info("Rotating integrity signature for the newly restored and encrypted files.")
            if not sfm.rotate_integrity_signature():
                raise Exception("Failed to rotate integrity signature after restore.")
            logger.info("Integrity signature updated successfully.")
        except Exception as e:
            logger.error(f"A critical error occurred during re-encryption: {e}", exc_info=True)
            shutil.rmtree(tempdir, ignore_errors=True)
            raise BackupError(f"Failed to re-encrypt restored files: {e}") from e
    else:
        logger.warning("No master password provided. Restored files will NOT be re-encrypted.")
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    moved = []
    backups_created = []

    logger.info("Moving restored files into vault directory...")
    for f in restored_files:
        basename = os.path.basename(f)
        if basename == "backup_manifest.json":
            # optional: read manifest if you need metadata
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

    # cleanup any remaining files in tempdir
    try:
        logger.info(f"Cleaning up temporary directory: {tempdir}")
        shutil.rmtree(tempdir)
    except Exception:
        logger.warning(f"Failed to clean up temporary directory: {tempdir}", exc_info=True)
        pass
    
    logger.info(f"Restore complete. Moved {len(moved)} files, created {len(backups_created)} backups.")
    return {"restored_to": moved, "backups_created": backups_created}
