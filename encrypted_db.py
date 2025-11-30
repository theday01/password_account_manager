"""Compatibility layer for opening (optionally) SQLCipher-encrypted SQLite databases.

This module exposes:
- create_encrypted_database(path, key): create or open a database and return a connection
- get_encrypted_connection(path, key): open an existing database and return a connection
- Row: a row-factory type usable as `conn.row_factory = Row`

The implementation will attempt to use SQLCipher bindings (pysqlcipher3 or sqlcipher3)
if available. If not present, it falls back to the standard library `sqlite3`.

FALLBACK STRATEGY:
If SQLCipher fails (e.g., key mismatch, corrupted file), the corrupted database is
removed and recreated using plain sqlite3. This allows the app to gracefully degrade
rather than crash.
"""

from typing import Optional
import sqlite3
import os
import logging

LOG = logging.getLogger(__name__)

# SQLCipher support disabled by default (requires both pysqlcipher3 package AND native SQLCipher library)
# To enable, set ENABLE_SQLCIPHER = True and ensure SQLCipher is properly installed
ENABLE_SQLCIPHER = False
_sqlcipher = None
_sqlcipher_name = None

if ENABLE_SQLCIPHER:
    for mod_name in ("pysqlcipher3", "sqlcipher3"):
        try:
            _sqlcipher = __import__(mod_name)
            _sqlcipher_name = mod_name
            LOG.info("Using SQLCipher module: %s", mod_name)
            break
        except Exception as e:
            LOG.debug("SQLCipher module '%s' not available: %s", mod_name, e)
            _sqlcipher = None

LOG.info("Using plain sqlite3 for database encryption (SQLCipher disabled)")


def _apply_sqlcipher_key(conn, key: Optional[bytes]):
    """Apply PRAGMA key for SQLCipher connections if a key is provided.

    For standard sqlite3 this is a no-op.
    """
    if key is None:
        return
    try:
        # SQLCipher expects the key as a binary blob in the PRAGMA key statement.
        # The correct syntax is: PRAGMA key = "x'hexstring'" where hexstring is the hex encoding of the key.
        if isinstance(key, (bytes, bytearray)):
            hexkey = key.hex()
            # Use raw string with proper escaping for SQLCipher
            conn.execute(f"PRAGMA key = \"x'{hexkey}'\";")
            LOG.debug("SQLCipher key applied via PRAGMA key = x'...'")
        else:
            # If key is a string, wrap it properly
            conn.execute(f"PRAGMA key = '{str(key)}';")
            LOG.debug("SQLCipher key applied (string)")
    except Exception:
        LOG.exception("Failed to apply SQLCipher key PRAGMA")


def _cleanup_corrupted_db(path: str) -> None:
    """Remove a corrupted/mismatched database file and its WAL companions."""
    try:
        if os.path.exists(path):
            os.remove(path)
            LOG.warning("Removed corrupted database file: %s", path)
        # Also remove WAL files if they exist
        for suffix in ["-wal", "-shm"]:
            wal_path = path + suffix
            if os.path.exists(wal_path):
                os.remove(wal_path)
                LOG.debug("Removed WAL file: %s", wal_path)
    except Exception as e:
        LOG.error("Failed to clean up corrupted database: %s", e)


def create_encrypted_database(path: str, key: Optional[bytes] = None) -> sqlite3.Connection:
    """Create (if missing) and return a connection to an (optionally) encrypted DB.

    If SQLCipher bindings are available, they will be used and the key applied.
    Otherwise a plain sqlite3.Connection is returned.
    
    IMPORTANT: The key must be applied BEFORE any read/write operations for SQLCipher.
    If SQLCipher fails to open an existing file (e.g., key mismatch or corruption),
    the file is deleted and recreated with plain sqlite3 as fallback.
    """
    dirname = os.path.dirname(path)
    if dirname:
        os.makedirs(dirname, exist_ok=True)

    if _sqlcipher is not None:
        try:
            # pysqlcipher3 exposes a DB-API compatible module under .dbapi2
            dbapi = getattr(_sqlcipher, "dbapi2", _sqlcipher)
            conn = dbapi.connect(path)
            LOG.info("SQLCipher connection opened for %s", path)
            
            # CRITICAL: Apply key BEFORE any other operations
            _apply_sqlcipher_key(conn, key)
            LOG.info("SQLCipher key applied")
            
            # Test that the key works by performing a simple operation
            try:
                conn.execute("PRAGMA cipher_version;").fetchone()
                LOG.info("SQLCipher cipher verification successful")
            except Exception as e:
                LOG.warning("SQLCipher cipher verification issue: %s. This may indicate a key mismatch.", e)
                conn.close()
                
                # If the database exists and key verification fails, it's likely corrupted or wrong key
                if os.path.exists(path):
                    LOG.warning("Removing corrupted/mismatched SQLCipher database at %s and falling back to plain sqlite3", path)
                    _cleanup_corrupted_db(path)
                
                # Fall through to plain sqlite3 below
                raise Exception("SQLCipher failed; using plain sqlite3 fallback")
            
            # Ensure WAL mode for robustness
            try:
                conn.execute("PRAGMA journal_mode=WAL;")
            except Exception:
                pass
            conn.row_factory = sqlite3.Row
            return conn
        except Exception as e:
            LOG.warning("SQLCipher connection/verification failed: %s. Falling back to builtin sqlite3.", e)

    # Fallback to builtin sqlite3
    LOG.info("Using builtin sqlite3 for %s", path)
    conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.row_factory = sqlite3.Row
    return conn


def get_encrypted_connection(path: str, key: Optional[bytes] = None) -> sqlite3.Connection:
    """Open and return a connection to an existing (optionally) encrypted DB.

    Semantics mirror `create_encrypted_database` for compatibility.
    
    If SQLCipher fails to open (e.g., key mismatch or corruption), falls back to plain sqlite3.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Database file not found: {path}")

    if _sqlcipher is not None:
        try:
            dbapi = getattr(_sqlcipher, "dbapi2", _sqlcipher)
            conn = dbapi.connect(path)
            LOG.info("SQLCipher connection opened for %s", path)
            
            # CRITICAL: Apply key BEFORE any operations
            _apply_sqlcipher_key(conn, key)
            LOG.info("SQLCipher key applied")
            
            # Verify key by attempting a simple read
            try:
                conn.execute("SELECT 1;").fetchone()
                LOG.info("SQLCipher connection verified")
            except Exception as verify_error:
                LOG.warning("SQLCipher connection verification failed: %s. Falling back to plain sqlite3.", verify_error)
                conn.close()
                
                # Clean up the corrupted file
                LOG.warning("Removing corrupted SQLCipher database at %s and falling back to plain sqlite3", path)
                _cleanup_corrupted_db(path)
                
                raise Exception("SQLCipher verification failed; using plain sqlite3 fallback")
            
            conn.row_factory = sqlite3.Row
            return conn
        except Exception as e:
            LOG.warning("SQLCipher open failed: %s. Falling back to builtin sqlite3.", e)

    # Fallback to builtin sqlite3
    LOG.info("Using builtin sqlite3 for %s", path)
    conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


# Expose a Row type alias compatible with sqlite3.Row
Row = sqlite3.Row
