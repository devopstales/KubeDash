"""Minimal-config mode utilities."""

import os
import platform
from pathlib import Path


def get_minimal_db_path() -> str:
    """Resolve the default SQLite database path for minimal-config mode.

    Priority:
    1. $MINIMAL_DB_PATH environment variable (explicit override)
    2. $XDG_DATA_HOME/kubedash/kubedash.sqlite (Linux/macOS)
    3. ~/.local/share/kubedash/kubedash.sqlite (fallback)
    4. ./kubedash.sqlite (last resort, relative to CWD)

    Returns:
        str: Absolute path to the SQLite database file.
    """
    # Explicit environment variable override
    env_path = os.environ.get('MINIMAL_DB_PATH')
    if env_path:
        return os.path.abspath(env_path)

    # Try XDG_DATA_HOME
    xdg_data = os.environ.get('XDG_DATA_HOME')
    if xdg_data:
        db_dir = Path(xdg_data) / 'kubedash'
    else:
        # Fallback to ~/.local/share/kubedash
        home = Path.home()
        if platform.system() == 'Windows':
            db_dir = home / 'AppData' / 'Local' / 'kubedash'
        else:
            db_dir = home / '.local' / 'share' / 'kubedash'

    try:
        db_dir.mkdir(parents=True, exist_ok=True)
        db_path = db_dir / 'kubedash.sqlite'
        # Test writability
        db_path.touch()
        return str(db_path.absolute())
    except (PermissionError, OSError):
        # Last resort: relative path
        return str(Path('./kubedash.sqlite').absolute())
