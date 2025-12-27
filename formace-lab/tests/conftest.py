"""Pytest bootstrap helpers."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Importing runpaths prints the output root immediately for every pytest run.
import runpaths as _runpaths  # noqa: F401


def pytest_report_header(config):
    """Show the active run directory in pytest's header."""
    _ = config
    return f"[formace] Output root: {_runpaths.output_root()}"
