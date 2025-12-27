"""Shared helpers for timestamped output directories."""

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# Environment knobs to keep runs grouped when needed
RUN_ID_ENV = "FORMACE_RUN_ID"
OUTPUT_BASE_ENV = "FORMACE_OUTPUT_BASE"

# Project root is one level up from this src/ package
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _resolve_run_id() -> str:
    run_id = os.environ.get(RUN_ID_ENV)
    if run_id:
        return run_id
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.environ[RUN_ID_ENV] = run_id
    return run_id


RUN_ID = _resolve_run_id()
OUTPUT_BASE = Path(os.environ.get(OUTPUT_BASE_ENV, PROJECT_ROOT / "output"))

# Legacy behavior - for backward compatibility
RUN_ROOT = OUTPUT_BASE / RUN_ID
RUN_ROOT.mkdir(parents=True, exist_ok=True)
print(f"[formace] Output root: {RUN_ROOT}", file=sys.stderr)


def get_run_id() -> str:
    """Return the stable identifier for the current execution batch."""
    return RUN_ID


def output_root() -> Path:
    """Return the top-level output directory for the current run."""
    return RUN_ROOT


def ensure_subdir(*parts: str) -> Path:
    """Return a child directory under the run root, creating parents."""
    path = RUN_ROOT.joinpath(*parts)
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_benchmark_output_dir(
    case_name: str, benchmark_set: str, timestamp: Optional[str] = None
) -> Path:
    """Get output directory for new benchmark-centric architecture.

    Args:
        case_name: Case name (cache_hierarchy, exploration_labs, self_implementation)
        benchmark_set: Benchmark set name (smoky, heuristic, specint2k17, customized)
        timestamp: Optional timestamp override (default: uses current RUN_ID)

    Returns:
        Path to output directory: output/<timestamp>_<case_name>_<benchmark_set>/
    """
    ts = timestamp or RUN_ID
    dir_name = f"{ts}_{case_name}_{benchmark_set}"
    output_dir = OUTPUT_BASE / dir_name
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir
