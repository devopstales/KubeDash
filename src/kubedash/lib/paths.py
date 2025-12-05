"""
Path constants for KubeDash.

This module is intentionally kept minimal with no Flask dependencies
to allow imports in gunicorn_conf.py without triggering eventlet issues.
"""
from pathlib import Path

KUBEDASH_ROOT = Path(__file__).parent.parent
PROJECT_ROOT = KUBEDASH_ROOT.parent
