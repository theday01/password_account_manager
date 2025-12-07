import os
from pathlib import Path

base_path = Path(os.getenv('LOCALAPPDATA')) / 'SecureVaultPro'
for name in ['.integrity_check', '.system_state', '.verification']:
    tripwire = base_path / name
    if tripwire.exists():
        tripwire.unlink()
        print(f"Deleted: {tripwire}")