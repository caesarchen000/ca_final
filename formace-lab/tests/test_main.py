"""
test_main.py - pytest tests for main.py

Run with:
    pytest tests/
    pytest tests/test_main.py -v
    pytest tests/ --cov=main
"""

import os
import sys
from pathlib import Path

import pytest

# Add parent directory to path to import main
sys.path.insert(0, str(Path(__file__).parent.parent))

import main


class TestConstants:
    """Test main.py constants and configuration."""

    def test_benchmarks_defined(self):
        """BENCHMARKS dictionary should be defined."""
        assert isinstance(main.BENCHMARKS, dict)
        assert len(main.BENCHMARKS) > 0

    def test_benchmark_groups_defined(self):
        """BENCHMARK_GROUPS dictionary should be defined."""
        assert isinstance(main.BENCHMARK_GROUPS, dict)
        assert "heuristic" in main.BENCHMARK_GROUPS
        assert "microbench" in main.BENCHMARK_GROUPS

    def test_cache_policy_choices(self):
        """CACHE_POLICY_CHOICES should be defined."""
        assert isinstance(main.CACHE_POLICY_CHOICES, dict)
        assert "lru" in main.CACHE_POLICY_CHOICES
        assert "fifo" in main.CACHE_POLICY_CHOICES
        assert "treeplru" in main.CACHE_POLICY_CHOICES

    def test_branch_predictor_choices(self):
        """BRANCH_PREDICTOR_CHOICES should be defined."""
        assert isinstance(main.BRANCH_PREDICTOR_CHOICES, dict)
        assert "localbp" in main.BRANCH_PREDICTOR_CHOICES
        assert "bimodebp" in main.BRANCH_PREDICTOR_CHOICES

    def test_upstream_prefetcher_choices(self):
        """PREFETCHER_CHOICES should be defined."""
        assert isinstance(main.PREFETCHER_CHOICES, dict)
        assert "strideprefetcher" in main.PREFETCHER_CHOICES

    def test_ghb_prefetcher_choices(self):
        """GHB_PREFETCHER_CHOICES should be defined."""
        assert isinstance(main.GHB_PREFETCHER_CHOICES, dict)
        assert "baselinestride" in main.GHB_PREFETCHER_CHOICES
        assert "ghb_litestudent" in main.GHB_PREFETCHER_CHOICES

    def test_gem5_home_variable(self):
        """GEM5_HOME should be a string."""
        assert isinstance(main.GEM5_HOME, str)

    def test_script_dir_exists(self):
        """SCRIPT_DIR should exist."""
        assert main.SCRIPT_DIR.exists()
        assert main.SCRIPT_DIR.is_dir()


class TestBenchmarks:
    """Test benchmark definitions."""

    @pytest.mark.parametrize("bench_name", [
        "coremark",
        "dhrystone",
        "mm",
        "vvadd",
        "qsort",
        "stream",
        "towers",
        "pointer_chase",
        "binary_search",
        "branch_corr",
        "branch_bias",
        "cache_thrash",
        "smoky",
    ])
    def test_benchmark_defined(self, bench_name):
        """All expected benchmarks should be defined."""
        assert bench_name in main.BENCHMARKS

    @pytest.mark.parametrize("bench_name,bench_path", [
        ("coremark", "benchmarks/coremark/coremark.exe"),
        ("dhrystone", "benchmarks/dhrystone/dhrystone.riscv"),
        ("mm", "benchmarks/algo/mm.riscv"),
        ("vvadd", "benchmarks/algo/vvadd.riscv"),
        ("qsort", "benchmarks/algo/qsort.riscv"),
        ("stream", "benchmarks/algo/stream.riscv"),
        ("towers", "benchmarks/algo/towers.riscv"),
        ("pointer_chase", "benchmarks/algo/pointer_chase.riscv"),
        ("binary_search", "benchmarks/algo/binary_search.riscv"),
        ("branch_corr", "benchmarks/synthetic/branch-patterns/branch_corr.riscv"),
        ("branch_bias", "benchmarks/synthetic/branch-patterns/branch_bias.riscv"),
        ("cache_thrash", "benchmarks/synthetic/replacement-policy/cache_thrash.riscv"),
    ])
    def test_benchmark_file_exists(self, bench_name, bench_path):
        """All benchmark files should exist."""
        full_path = main.SCRIPT_DIR / bench_path
        assert full_path.exists(), f"Benchmark '{bench_name}' not found at {full_path}"


class TestFunctions:
    """Test function existence and basic behavior."""

    def test_check_venv_exists(self):
        """check_venv function should exist."""
        assert callable(main.check_venv)

    def test_check_venv_runs(self):
        """check_venv should run without error."""
        # Should not raise exception
        main.check_venv()

    def test_check_gem5_home_exists(self):
        """check_gem5_home function should exist."""
        assert callable(main.check_gem5_home)

    def test_execute_experiment_exists(self):
        """execute_experiment function should exist."""
        assert callable(main.execute_experiment)

    def test_run_suite_exists(self):
        """run_suite function should exist."""
        assert callable(main.run_suite)


class TestSuiteHandlers:
    """Test suite command handler functions."""

    def test_suite_cache_size_exists(self):
        """suite_cache_size function should exist."""
        assert callable(main.suite_cache_size)

    def test_suite_cache_policy_exists(self):
        """suite_cache_policy function should exist."""
        assert callable(main.suite_cache_policy)

    def test_suite_branch_exists(self):
        """suite_branch function should exist."""
        assert callable(main.suite_branch)

    def test_suite_prefetch_upstream_exists(self):
        """suite_prefetch_upstream function should exist."""
        assert callable(main.suite_prefetch_upstream)

    def test_suite_prefetch_ghb_exists(self):
        """suite_prefetch_ghb function should exist."""
        assert callable(main.suite_prefetch_ghb)


class TestLegacyCommandHandlers:
    """Test legacy command handler functions."""

    def test_cmd_test_exists(self):
        """cmd_test function should exist."""
        assert callable(main.cmd_test)

    def test_cmd_metrics_exists(self):
        """cmd_metrics function should exist."""
        assert callable(main.cmd_metrics)

    def test_cmd_list_exists(self):
        """cmd_list function should exist."""
        assert callable(main.cmd_list)

    def test_main_function_exists(self):
        """main function should exist."""
        assert callable(main.main)


class TestScriptFiles:
    """Test required script files exist."""

    def test_src_modules_exist(self):
        """All src modules should exist."""
        src_dir = main.SCRIPT_DIR / "src"
        assert src_dir.exists(), "src/ directory not found"
        assert (src_dir / "__init__.py").exists(), "__init__.py not found"
        assert (src_dir / "simulator.py").exists(), "simulator.py not found"
        assert (src_dir / "stats.py").exists(), "stats.py not found"
        assert (src_dir / "metrics.py").exists(), "metrics.py not found"
        assert (src_dir / "benchmarks.py").exists(), "benchmarks.py not found"
        assert (src_dir / "runpaths.py").exists(), "runpaths.py not found"

    def test_main_py_exists(self):
        """main.py should exist and be executable."""
        main_script = main.SCRIPT_DIR / "main.py"
        assert main_script.exists(), "main.py not found"
        assert os.access(main_script, os.X_OK), "main.py is not executable"


class TestDocumentation:
    """Test documentation files exist."""

    def test_readme_exists(self):
        """README.md should exist."""
        doc = main.SCRIPT_DIR / "README.md"
        assert doc.exists(), "README.md not found"


class TestMetricsExtraction:
    """Test metrics extraction functionality."""

    def test_extract_metrics_returns_dict(self):
        """extract_metrics_from_stats should return a dict."""
        result = main.extract_metrics_from_stats(Path("/nonexistent"))
        assert isinstance(result, dict)

    def test_extract_stat_with_invalid_file(self):
        """extract_stat should handle invalid file gracefully."""
        result = main.extract_stat(Path("/nonexistent"), r"^test\s")
        assert result == "N/A"


@pytest.mark.skipif(
    not main.GEM5_HOME,
    reason="GEM5_HOME not set"
)
class TestGem5Environment:
    """Test gem5 environment setup (requires GEM5_HOME)."""

    def test_gem5_home_set(self):
        """GEM5_HOME should be set."""
        assert main.GEM5_HOME, "GEM5_HOME not set"

    def test_gem5_binary_exists(self):
        """gem5.debug or gem5.fast binary should exist."""
        gem5_home = Path(main.GEM5_HOME)
        gem5_debug = gem5_home / "build" / "RISCV" / "gem5.debug"
        gem5_fast = gem5_home / "build" / "RISCV" / "gem5.fast"
        assert gem5_debug.exists() or gem5_fast.exists(), \
            f"gem5 binary not found at {gem5_debug} or {gem5_fast}"

    def test_check_gem5_home_succeeds(self):
        """check_gem5_home should succeed when GEM5_HOME is set."""
        gem5_path = main.check_gem5_home()
        assert gem5_path.exists()
        # Should have either gem5.debug or gem5.fast
        assert (gem5_path / "build" / "RISCV" / "gem5.debug").exists() or \
               (gem5_path / "build" / "RISCV" / "gem5.fast").exists()


class TestNocacheOptimization:
    """Test that nocache parameter exists and has correct default values."""

    def test_execute_experiment_has_run_nocache_param(self):
        """execute_experiment should have run_nocache parameter."""
        import inspect
        sig = inspect.signature(main.execute_experiment)
        assert "run_nocache" in sig.parameters
        # Default should be True
        assert sig.parameters["run_nocache"].default is True

    def test_run_suite_has_run_nocache_param(self):
        """run_suite should have run_nocache parameter."""
        import inspect
        sig = inspect.signature(main.run_suite)
        assert "run_nocache" in sig.parameters
        # Default should be True
        assert sig.parameters["run_nocache"].default is True
