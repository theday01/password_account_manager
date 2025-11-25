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
    
    CRITICAL: This function restores ONLY account database files, NOT master account files:
    - Restores: metadata.db, sensitive.db, integrity_file (account data)
    - Preserves: salt_file and other master account authentication files
    - User can still log in with their current master password
    
    The account databases should be deleted before calling this function
    to ensure a clean restore without conflicts.
    
    Returns dict with details about restored and backed-up files.
    """
    logger.info(f"Attempting to restore backup from {backup_path} into vault {vault_dir}")
    
    if not os.path.exists(backup_path):
        logger.error(f"Backup file not found: {backup_path}")
        raise FileNotFoundError(f"Backup file not found: {backup_path}")

    # Ensure vault directory exists (should already exist with master account)
    os.makedirs(vault_dir, exist_ok=True)
    logger.info(f"Using vault directory: {vault_dir}")
    
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
    logger.info("Skipping re-encryption of backup files.")
    logger.info("The backup files are already properly encrypted.")

    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    moved = []
    backups_created = []
    
    # Files to restore (ONLY account data, NOT master account)
    account_files_to_restore = [metadata_name, sensitive_name, integrity_name]

    logger.info("Moving restored account database files into vault directory...")
    for f in restored_files:
        basename = os.path.basename(f)
        
        # Skip manifest file
        if basename == "backup_manifest.json":
            logger.debug(f"Skipping manifest file: {basename}")
            continue
        
        # CRITICAL: Skip master account files - do not restore them
        if basename == salt_name:
            logger.info(f"⚠️ Skipping master account file: {basename} (preserving current master account)")
            continue
        
        # Only restore account database files
        if basename not in account_files_to_restore:
            logger.info(f"⚠️ Skipping non-account file: {basename}")
            continue

        dest = os.path.join(vault_dir, basename)
        
        # Backup should have been created before calling this function
        # But double-check just in case
        if os.path.exists(dest):
            bak_name = f"{dest}.bak.{timestamp}"
            logger.warning(f"File still exists (should have been deleted): {dest}")
            logger.info(f"Creating additional backup: {bak_name}")
            shutil.copy2(dest, bak_name)
            backups_created.append(bak_name)

        logger.info(f"Moving account database {basename} to {dest}")
        shutil.move(f, dest)
        moved.append(dest)
    
    # IMPORTANT: Verify all critical account files are restored
    critical_account_files = [
        os.path.join(vault_dir, metadata_name),
        os.path.join(vault_dir, sensitive_name)
    ]
    
    for crit_file in critical_account_files:
        if not os.path.exists(crit_file):
            logger.error(f"CRITICAL: Required account file missing after restore: {crit_file}")
            shutil.rmtree(tempdir, ignore_errors=True)
            raise FileNotFoundError(f"Critical account file missing after restore: {crit_file}")
        logger.info(f"✓ Verified account file exists: {os.path.basename(crit_file)}")
    
    # Verify master account file is still present (not overwritten)
    master_salt_file = os.path.join(vault_dir, salt_name)
    if os.path.exists(master_salt_file):
        logger.info(f"✓ Master account file preserved: {salt_name}")
    else:
        logger.warning(f"⚠️ Master account file not found: {salt_name}")
        logger.warning("User may need to re-authenticate")

    # cleanup temporary directory
    try:
        logger.info(f"Cleaning up temporary directory: {tempdir}")
        shutil.rmtree(tempdir)
    except Exception as e:
        logger.warning(f"Failed to clean up temporary directory: {tempdir}: {e}")
        pass
    
    logger.info(f"Restore complete. Moved {len(moved)} account files, created {len(backups_created)} backups.")
    logger.info("✓ Master account preserved - user can log in with current password")
    logger.info("✓ Account databases restored from backup")
    logger.info("IMPORTANT: The application must be restarted for the restored data to be loaded.")
    
    return {"restored_to": moved, "backups_created": backups_created}


    