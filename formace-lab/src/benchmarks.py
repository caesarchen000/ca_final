"""
Benchmark registry for formace-lab.

Manages benchmark sets and provides utilities for benchmark lookup and validation.
"""

from pathlib import Path
from typing import Dict, List, Optional

# Root directory (formace-lab/)
SCRIPT_DIR = Path(__file__).parent.parent.resolve()

# Benchmark sets organized by category
BENCHMARK_SETS: Dict[str, Dict[str, str]] = {
    "smoky": {
        "dhrystone": "benchmarks/smoky/dhrystone.riscv",
    },
    "heuristic": {
        "mm": "benchmarks/heuristic/mm.riscv",
        "vvadd": "benchmarks/heuristic/vvadd.riscv",
        "qsort": "benchmarks/heuristic/qsort.riscv",
        "stream": "benchmarks/heuristic/stream.riscv",
        "towers": "benchmarks/heuristic/towers.riscv",
    },
    "specint2k17": {
        # TBD: To be populated when SPEC CPU 2017 is purchased
    },
    "customized": {
        # TBD: To be populated with adjusted SPEC benchmarks
    },
}

# Metadata for benchmarks (descriptions, expected runtime, etc.)
BENCHMARK_METADATA = {
    "smoky": {
        "dhrystone": {
            "description": "Classic integer benchmark (Dhrystone)",
            "runtime": "fast",  # < 1 minute
            "characteristics": ["integer-heavy", "control-flow"],
        },
    },
    "heuristic": {
        "mm": {
            "description": "Matrix multiplication (64x64)",
            "runtime": "fast",  # 1-3 minutes
            "characteristics": ["cache-friendly", "2D-access", "compute-intensive"],
        },
        "vvadd": {
            "description": "Vector addition (1M elements)",
            "runtime": "fast",
            "characteristics": ["streaming", "prefetch-friendly", "memory-bound"],
        },
        "qsort": {
            "description": "Quicksort (10K elements)",
            "runtime": "fast",
            "characteristics": ["irregular-access", "branch-heavy"],
        },
        "stream": {
            "description": "STREAM memory bandwidth benchmark",
            "runtime": "fast",
            "characteristics": ["memory-bound", "streaming", "bandwidth-intensive"],
        },
        "towers": {
            "description": "Towers of Hanoi (20 disks)",
            "runtime": "fast",
            "characteristics": ["recursive", "control-flow", "compute-bound"],
        },
    },
}


def get_benchmark_set(set_name: str) -> Dict[str, str]:
    """
    Get all benchmarks in a set.

    Args:
        set_name: Name of benchmark set (smoky, heuristic, specint2k17, customized)

    Returns:
        Dictionary mapping benchmark name to relative path

    Raises:
        ValueError: If benchmark set doesn't exist
    """
    if set_name not in BENCHMARK_SETS:
        raise ValueError(
            f"Unknown benchmark set '{set_name}'. "
            f"Available: {list(BENCHMARK_SETS.keys())}"
        )

    benchmark_dict = BENCHMARK_SETS[set_name]

    if not benchmark_dict:
        raise ValueError(
            f"Benchmark set '{set_name}' is empty. "
            f"This set may not be configured yet (e.g., specint2k17, customized)."
        )

    return benchmark_dict


def get_benchmark_path(set_name: str, bench_name: str) -> Path:
    """
    Get absolute path to a benchmark binary.

    Args:
        set_name: Benchmark set name
        bench_name: Benchmark name within the set

    Returns:
        Absolute path to benchmark binary

    Raises:
        ValueError: If set or benchmark doesn't exist
        FileNotFoundError: If benchmark binary doesn't exist on disk
    """
    benchmark_set = get_benchmark_set(set_name)

    if bench_name not in benchmark_set:
        raise ValueError(
            f"Benchmark '{bench_name}' not found in set '{set_name}'. "
            f"Available: {list(benchmark_set.keys())}"
        )

    rel_path = benchmark_set[bench_name]
    abs_path = SCRIPT_DIR / rel_path

    if not abs_path.exists():
        raise FileNotFoundError(
            f"Benchmark binary not found: {abs_path}\n"
            f"Expected location: {rel_path}"
        )

    return abs_path


def list_benchmark_sets() -> List[str]:
    """Get list of available benchmark sets."""
    return list(BENCHMARK_SETS.keys())


def list_benchmarks(set_name: str) -> List[str]:
    """
    Get list of benchmark names in a set.

    Args:
        set_name: Benchmark set name

    Returns:
        List of benchmark names

    Raises:
        ValueError: If set doesn't exist or is empty
    """
    benchmark_set = get_benchmark_set(set_name)
    return list(benchmark_set.keys())


def get_benchmark_metadata(set_name: str, bench_name: str) -> Optional[Dict]:
    """
    Get metadata for a benchmark (description, characteristics, etc.).

    Args:
        set_name: Benchmark set name
        bench_name: Benchmark name

    Returns:
        Metadata dictionary, or None if no metadata available
    """
    if set_name in BENCHMARK_METADATA:
        return BENCHMARK_METADATA[set_name].get(bench_name)
    return None


def validate_benchmark_set(set_name: str) -> bool:
    """
    Validate that all benchmarks in a set exist on disk.

    Args:
        set_name: Benchmark set name

    Returns:
        True if all benchmarks exist, False otherwise
    """
    try:
        benchmark_set = get_benchmark_set(set_name)
    except ValueError:
        return False

    for bench_name in benchmark_set:
        try:
            get_benchmark_path(set_name, bench_name)
        except FileNotFoundError:
            return False

    return True


def print_benchmark_info(set_name: Optional[str] = None):
    """
    Print information about available benchmarks.

    Args:
        set_name: If provided, only show this set. Otherwise show all.
    """
    if set_name:
        sets_to_show = [set_name]
    else:
        sets_to_show = list_benchmark_sets()

    for s in sets_to_show:
        try:
            benchmarks = list_benchmarks(s)
            print(f"\n{s}:")
            for b in benchmarks:
                path = get_benchmark_path(s, b)
                exists = "✓" if path.exists() else "✗"
                metadata = get_benchmark_metadata(s, b)
                desc = metadata.get("description", "No description") if metadata else "No description"
                print(f"  {exists} {b:<20} - {desc}")
        except ValueError as e:
            print(f"\n{s}: {e}")


if __name__ == "__main__":
    # Test/debug mode
    print("Benchmark Registry")
    print("=" * 80)
    print_benchmark_info()
