"""
Backup File Validator Utility

This script checks all .svbk files in the backups folder and reports which ones
are valid SecureVault backup files and which ones have issues.
"""
import os
import sys
import logging
from backup_manager import BackupManager

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def validate_all_backups():
    """Check all backup files in the backups folder."""
    
    backups_dir = os.path.join(os.getcwd(), "backups")
    
    if not os.path.exists(backups_dir):
        logger.error(f"❌ Backups directory does not exist: {backups_dir}")
        return
    
    # Create a dummy BackupManager for validation
    bm = BackupManager(
        metadata_db_path="dummy.db",
        sensitive_db_path="dummy2.db",
        salt_path="dummy_salt",
        integrity_path="dummy_integrity",
        backups_dir=backups_dir
    )
    
    # Get all .svbk files
    backup_files = sorted([
        os.path.join(backups_dir, f) 
        for f in os.listdir(backups_dir) 
        if f.endswith('.svbk')
    ], reverse=True)
    
    if not backup_files:
        logger.warning(f"⚠️ No .svbk backup files found in {backups_dir}")
        return
    
    logger.info(f"\\n{'='*70}")
    logger.info(f"Found {len(backup_files)} backup file(s) to validate")
    logger.info(f"{'='*70}\\n")
    
    valid_count = 0
    invalid_count = 0
    
    for i, backup_path in enumerate(backup_files, 1):
        filename = os.path.basename(backup_path)
        file_size = os.path.getsize(backup_path)
        
        logger.info(f"\\n[{i}/{len(backup_files)}] Checking: {filename}")
        logger.info(f"  Size: {file_size:,} bytes")
        
        # Validate the backup
        try:
            backup_info = bm.get_backup_info(backup_path)
            header_result = bm._get_backup_header_and_offset(backup_path)
            
            if header_result:
                header, offset = header_result
                valid_count += 1
                logger.info(f"  ✅ VALID - Version: {backup_info['version']}, IV Length: {backup_info['iv_length']} bytes")
                if offset > 0:
                    logger.info(f"     Note: Has {offset}-byte signature prefix")
            else:
                invalid_count += 1
                logger.error(f"  ❌ INVALID - Bad header (see details above)")
                
        except Exception as e:
            invalid_count += 1
            logger.error(f"  ❌ ERROR - {str(e)}")
    
    # Summary
    logger.info(f"\\n{'='*70}")
    logger.info(f"VALIDATION SUMMARY")
    logger.info(f"{'='*70}")
    logger.info(f"✅ Valid backups:   {valid_count}")
    logger.info(f"❌ Invalid backups: {invalid_count}")
    logger.info(f"📊 Total files:     {len(backup_files)}")
    logger.info(f"{'='*70}\\n")
    
    if invalid_count > 0:
        logger.warning("⚠️ Some backup files are invalid. You may want to:")
        logger.warning("   1. Delete or move the invalid .svbk files")
        logger.warning("   2. Create new backups from your current vault")
        logger.warning("   3. Check if you have valid backups elsewhere")

if __name__ == "__main__":
    try:
        validate_all_backups()
    except KeyboardInterrupt:
        logger.info("\\n\\n❌ Validation interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\\n\\n❌ Unexpected error: {e}", exc_info=True)
        sys.exit(1)
