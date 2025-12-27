"""Batch testing utilities."""

import csv
from pathlib import Path
from typing import Dict, List, Optional

from simulator import run_gem5
from stats import extract_metrics_from_stats


def run_single_test(
    benchmark: str,
    bench_path: str,
    config: str,
    config_flags: List[str],
    output_dir: Path,
    cpu: str = "TimingSimpleCPU",
    mem: str = "1GB",
    bp_type: Optional[str] = None,
    gem5_home: str = "",
) -> Optional[Dict[str, str]]:
    """Run a single test configuration.

    Args:
        benchmark: Benchmark name
        bench_path: Path to benchmark binary
        config: Config name
        config_flags: Configuration flags
        output_dir: Output directory
        cpu: CPU type
        mem: Memory size
        gem5_home: gem5 installation path

    Returns:
        Metrics dictionary or None if failed
    """
    print()
    print("=" * 60)
    print(f"Benchmark: {benchmark}")
    print(f"Config:    {config}")
    print(f"Flags:     {' '.join(config_flags) if config_flags else 'none'}")
    print("=" * 60)

    test_output = output_dir / f"{benchmark}_{config}"

    # Parse flags
    enable_drrip = "--enable-drrip" in config_flags
    enable_ghb = "--enable-ghb-prefetch" in config_flags
    enable_tage = "--enable-tage-lite" in config_flags

    # Run nocache
    print(f"\n==> Running case: nocache")
    try:
        ret = run_gem5(
            prog=bench_path,
            output_dir=test_output,
            case="nocache",
            cpu=cpu,
            mem=mem,
            enable_drrip=enable_drrip,
            enable_ghb=enable_ghb,
            enable_tage=enable_tage,
            bp_type=bp_type,
            gem5_home=gem5_home,
        )
        if ret != 0:
            print(f"ERROR: nocache simulation failed")
            return None
    except Exception as e:
        print(f"ERROR: {e}")
        return None

    # Run caches
    print(f"\n==> Running case: caches")
    try:
        ret = run_gem5(
            prog=bench_path,
            output_dir=test_output,
            case="caches",
            cpu=cpu,
            mem=mem,
            enable_drrip=enable_drrip,
            enable_ghb=enable_ghb,
            enable_tage=enable_tage,
            bp_type=bp_type,
            gem5_home=gem5_home,
        )
        if ret != 0:
            print(f"ERROR: caches simulation failed")
            return None
    except Exception as e:
        print(f"ERROR: {e}")
        return None

    # Extract metrics
    stats_file = test_output / "caches" / "stats.txt"
    metrics = extract_metrics_from_stats(stats_file)

    if metrics and "ipc" in metrics:
        ipc = metrics.get("ipc", "N/A")
        print(f"✓ IPC: {ipc}")

    return metrics


def generate_csv_report(results: List[Dict[str, str]], output_file: Path) -> None:
    """Generate CSV report from results."""
    if not results:
        return

    fieldnames = list(results[0].keys())
    with output_file.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def print_summary_table(results: List[Dict[str, str]]) -> None:
    """Print IPC summary table."""
    print()
    print("Summary (IPC):")
    print()
    print(f"{'Benchmark':<15} {'Baseline':<10} {'DRRIP':<10} {'GHB':<10} {'TAGE':<10} {'All':<10}")
    print("-" * 65)

    # Group by benchmark
    by_bench: Dict[str, Dict[str, str]] = {}
    for row in results:
        bench = row["benchmark"]
        config = row["config"]
        ipc = row.get("ipc", "N/A")

        if bench not in by_bench:
            by_bench[bench] = {}
        by_bench[bench][config] = ipc

    for bench, configs in by_bench.items():
        print(
            f"{bench:<15} "
            f"{configs.get('baseline', 'N/A'):<10} "
            f"{configs.get('drrip', 'N/A'):<10} "
            f"{configs.get('ghb', 'N/A'):<10} "
            f"{configs.get('tage', 'N/A'):<10} "
            f"{configs.get('all', 'N/A'):<10}"
        )
