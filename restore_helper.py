import os
import shutil
import tempfile
from datetime import datetime
import logging

from backup_manager import BackupManager, BackupError

logger = logging.getLogger(__name__)

def restore_backup_into_vault(backup_path: str, backup_code: str, vault_dir: str,
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
