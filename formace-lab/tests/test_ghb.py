#!/usr/bin/env python3
"""
Lightweight wrapper that tests the ghb_history gtest target.
Requires GEM5_HOME to point to a tree with the ghb_history gtest target.
Each of the 4 gtest cases is wrapped as a separate pytest test.
"""

import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))
import main


def get_ghb_binary() -> Path:
    """Get the path to the ghb_history gtest binary."""
    gem5_root = Path(main.GEM5_HOME)
    binary = gem5_root / "build" / "RISCV" / "mem" / "cache" / "prefetch" / "ghb_history.test.opt"

    if not binary.exists():
        # Try to build it first
        build_cmd = [
            "scons",
            f"-j{os.cpu_count() or 1}",
            "build/RISCV/mem/cache/prefetch/ghb_history.test.opt",
        ]
        subprocess.run(build_cmd, cwd=gem5_root, capture_output=True)

    if not binary.exists():
        raise FileNotFoundError(f"GHB gtest binary not found at {binary}")

    return binary


def run_ghb_test_filter(test_filter: str) -> None:
    """Run ghb-test with a specific gtest filter."""
    binary = get_ghb_binary()
    cmd = [str(binary), f"--gtest_filter={test_filter}"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("\n=== STDOUT ===\n", result.stdout)
        print("\n=== STDERR ===\n", result.stderr, file=sys.stderr)
    assert result.returncode == 0, f"ghb-test {test_filter} failed"


def test_ghb_build_pattern_from_pc():
    """Test GHBHistoryTest.BuildPatternFromPC"""
    run_ghb_test_filter("GHBHistoryTest.BuildPatternFromPC")


def test_ghb_page_correlation_without_pc():
    """Test GHBHistoryTest.PageCorrelationWorksWithoutPC"""
    run_ghb_test_filter("GHBHistoryTest.PageCorrelationWorksWithoutPC")


def test_ghb_pattern_table_predicts():
    """Test GHBHistoryTest.PatternTablePredictsMostLikelyDelta"""
    run_ghb_test_filter("GHBHistoryTest.PatternTablePredictsMostLikelyDelta")


def test_ghb_fallback_recent_deltas():
    """Test GHBHistoryTest.FallbackUsesRecentDeltas"""
    run_ghb_test_filter("GHBHistoryTest.FallbackUsesRecentDeltas")
