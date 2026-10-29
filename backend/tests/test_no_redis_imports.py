"""ADR-0029/0030/0031 contract: Redis is gone from the stack.

A pure filesystem scan (no app fixture, no Docker): no module under
``backend/app/`` may reference ``redis_client`` or ``flask_redis``, and
``flask-redis`` must not be in ``pyproject.toml`` dependencies. Re-adding
either without updating this gate is a contract violation.
"""
from __future__ import annotations

import pathlib
import re

_APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"
_PYPROJECT = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_no_module_references_redis_client_or_flask_redis() -> None:
    hits: list[str] = []
    for p in sorted(_APP_DIR.rglob("*.py")):
        for n, line in enumerate(p.read_text().splitlines(), start=1):
            if "redis_client" in line or "flask_redis" in line:
                hits.append(f"{p.relative_to(_APP_DIR.parent)}:{n}: {line.strip()}")
    assert hits == [], "redis_client/flask_redis reference(s) left in app/:\n" + "\n".join(hits)


def test_flask_redis_not_in_pyproject_dependencies() -> None:
    deps_block = re.search(
        r"^dependencies = \[(.*?)^\]", _PYPROJECT.read_text(), re.M | re.S
    )
    assert deps_block is not None, "dependencies block not found in pyproject.toml"
    for dep in re.findall(r"\"([^\"]+)\",", deps_block.group(1)):
        assert not re.match(r"^flask[-_]redis\b", dep), f"{dep!r} still in dependencies"
