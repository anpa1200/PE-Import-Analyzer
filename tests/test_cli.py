"""CLI tests (--version, missing file exit code). Require lief to run script."""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("lief", reason="lief required for CLI tests")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = _PROJECT_ROOT / "PE-Import-Analyzer.py"


def test_version() -> None:
    """--version prints version and exits 0."""
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--version"],
        capture_output=True,
        text=True,
        cwd=str(_PROJECT_ROOT),
    )
    assert r.returncode == 0
    assert "PE-Import-Analyzer" in r.stdout or "2.0" in r.stdout


def test_missing_file_exit_code() -> None:
    """Missing file path exits non-zero."""
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "/nonexistent_pe_file_12345", "--no-prompt"],
        capture_output=True,
        text=True,
        cwd=str(_PROJECT_ROOT),
    )
    assert r.returncode != 0
    assert "not found" in r.stderr or "Error" in r.stderr or "required" in r.stderr


def test_required_file_path() -> None:
    """No file_path argument errors."""
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--no-prompt"],
        capture_output=True,
        text=True,
        cwd=str(_PROJECT_ROOT),
    )
    assert r.returncode != 0
    assert "required" in r.stderr.lower() or "file_path" in r.stderr
