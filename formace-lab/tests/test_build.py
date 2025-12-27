#!/usr/bin/env python3
"""
test_build.py - Tests for building gem5 binaries

Tests that gem5.fast and ghb_history.test.opt can be built successfully.
"""

import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))
import main


def test_build_gem5_fast():
    """Test that gem5.fast can be built."""
    gem5_root = Path(main.GEM5_HOME)
    gem5_binary = gem5_root / "build" / "RISCV" / "gem5.fast"

    # Try to build if not exists
    if not gem5_binary.exists():
        build_cmd = [
            "scons",
            f"-j{os.cpu_count() or 1}",
            "build/RISCV/gem5.fast",
        ]
        result = subprocess.run(build_cmd, cwd=gem5_root, capture_output=True, text=True)
        if result.returncode != 0:
            print("\n=== BUILD STDOUT ===\n", result.stdout)
            print("\n=== BUILD STDERR ===\n", result.stderr, file=sys.stderr)
        assert result.returncode == 0, f"Failed to build gem5.fast"

    # Verify binary exists
    assert gem5_binary.exists(), f"gem5.fast not found at {gem5_binary}"
    assert gem5_binary.is_file(), f"gem5.fast is not a file"
    assert os.access(gem5_binary, os.X_OK), f"gem5.fast is not executable"


def test_build_ghb_test():
    """Test that ghb_history.test.opt can be built."""
    gem5_root = Path(main.GEM5_HOME)
    ghb_binary = gem5_root / "build" / "RISCV" / "mem" / "cache" / "prefetch" / "ghb_history.test.opt"

    # Try to build if not exists
    if not ghb_binary.exists():
        build_cmd = [
            "scons",
            f"-j{os.cpu_count() or 1}",
            "build/RISCV/mem/cache/prefetch/ghb_history.test.opt",
        ]
        result = subprocess.run(build_cmd, cwd=gem5_root, capture_output=True, text=True)
        if result.returncode != 0:
            print("\n=== BUILD STDOUT ===\n", result.stdout)
            print("\n=== BUILD STDERR ===\n", result.stderr, file=sys.stderr)
        assert result.returncode == 0, f"Failed to build ghb_history.test.opt"

    # Verify binary exists
    assert ghb_binary.exists(), f"ghb_history.test.opt not found at {ghb_binary}"
    assert ghb_binary.is_file(), f"ghb_history.test.opt is not a file"
    assert os.access(ghb_binary, os.X_OK), f"ghb_history.test.opt is not executable"
