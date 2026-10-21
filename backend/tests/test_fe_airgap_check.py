# ADR-0020 air-gap check (frontend half) — unit tier, no Docker, drives the
# Taskfile-free script via a subprocess so CI can rely on the exact CLI
# contract: `node tests/fe-airgap-check.mjs <distDir> [--allow "a,b,c"]`.
from __future__ import annotations

import subprocess
from pathlib import Path

# node is a repo toolchain prereq (the frontend build needs it); CI installs
# it via corepack/pnpm. No version pin: the script is plain ESM.
NODE = "node"
REPO_ROOT = Path(__file__).resolve().parents[2]


def _run(dist: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [NODE, str(REPO_ROOT / "tests" / "fe-airgap-check.mjs"), str(dist), *extra],
        capture_output=True,
        text=True,
    )


def test_clean_dist_passes(tmp_path: Path) -> None:
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text('<script src="./assets/main.js"></script>')
    (tmp_path / "assets" / "main.js").write_text("console.log('hi')")
    r = _run(tmp_path)
    assert r.returncode == 0


def test_cdn_ref_fails_with_offender(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text('<script src="https://cdn.example.com/lib.js"></script>')
    r = _run(tmp_path)
    assert r.returncode == 1
    assert "index.html" in r.stdout and "https://cdn.example.com/lib.js" in r.stdout


def test_protocol_relative_cdn_fails(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text("x = '//cdn.foo.com/b.js'")
    r = _run(tmp_path)
    assert r.returncode == 1


def test_allow_list_overrides(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text('<script src="https://internal.example.com/lib.js"></script>')
    r = _run(tmp_path, "--allow", "internal.example.com")
    assert r.returncode == 0
