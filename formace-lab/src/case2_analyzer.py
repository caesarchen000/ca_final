#!/usr/bin/env python3
"""
Case 2 analysis module for exploration labs.

Extracts PMU counters and generates comparative analysis for:
- Case 2.1: Cache Replacement Policies
- Case 2.2: Branch Predictors
- Case 2.3: Prefetcher Configurations
"""

import csv
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict


@dataclass
class Case2Metrics:
    """Raw PMU metrics for Case 2 exploration labs"""
    config: str
    benchmark: str
    subcase: str  # "2.1", "2.2", or "2.3"

    # Common metrics
    ipc: float = 0.0
    num_cycles: int = 0
    committed_insts: int = 0

    # Cache metrics (for 2.1 and 2.3)
    l2_accesses: int = 0
    l2_misses: int = 0
    l2_hits: int = 0
    l2_miss_rate: float = 0.0
    l2_mpki: float = 0.0  # Misses Per Kilo Instructions

    # Branch prediction metrics (for 2.2)
    branch_mispredictions: int = 0
    branch_total: int = 0
    branch_mispredict_rate: float = 0.0
    branch_mpki: float = 0.0


def extract_stat(stats_content: str, pattern: str) -> Optional[float]:
    """Extract a single stat value using regex pattern."""
    match = re.search(pattern, stats_content, re.MULTILINE)
    if match:
        try:
            return float(match.group(1))
        except (ValueError, IndexError):
            return None
    return None


def extract_case2_metrics(stats_path: Path, config: str, benchmark: str, subcase: str) -> Case2Metrics:
    """Extract Case 2 metrics from stats.txt"""

    if not stats_path.exists():
        raise FileNotFoundError(f"Stats file not found: {stats_path}")

    with open(stats_path, 'r') as f:
        content = f.read()

    metrics = Case2Metrics(
        config=config,
        benchmark=benchmark,
        subcase=subcase
    )

    # Common metrics
    metrics.ipc = extract_stat(content, r'system\.cpu\.ipc\s+([\d.]+)') or 0.0
    metrics.num_cycles = int(extract_stat(content, r'system\.cpu\.numCycles\s+(\d+)') or 0)
    # O3CPU uses commitStats0.numInsts
    metrics.committed_insts = int(extract_stat(content, r'system\.cpu\.commitStats0\.numInsts\s+(\d+)') or 0)

    # Cache metrics (Case 2.1 and 2.3)
    if subcase in ["2.1", "2.3"]:
        metrics.l2_accesses = int(extract_stat(content, r'system\.l2\.demandAccesses::total\s+(\d+)') or 0)
        metrics.l2_misses = int(extract_stat(content, r'system\.l2\.demandMisses::total\s+(\d+)') or 0)
        metrics.l2_hits = int(extract_stat(content, r'system\.l2\.demandHits::total\s+(\d+)') or 0)
        metrics.l2_miss_rate = extract_stat(content, r'system\.l2\.demandMissRate::total\s+([\d.]+)') or 0.0

        # Calculate L2 MPKI
        if metrics.committed_insts > 0:
            metrics.l2_mpki = (metrics.l2_misses / metrics.committed_insts) * 1000

    # Branch prediction metrics (Case 2.2)
    if subcase == "2.2":
        metrics.branch_mispredictions = int(extract_stat(content, r'system\.cpu\.branchPred\.condIncorrect\s+(\d+)') or 0)
        metrics.branch_total = int(extract_stat(content, r'system\.cpu\.branchPred\.condPredicted\s+(\d+)') or 0)

        # Calculate branch misprediction rate
        if metrics.branch_total > 0:
            metrics.branch_mispredict_rate = metrics.branch_mispredictions / metrics.branch_total

        # Calculate branch MPKI
        if metrics.committed_insts > 0:
            metrics.branch_mpki = (metrics.branch_mispredictions / metrics.committed_insts) * 1000

    return metrics


def write_case2_metrics_csv(metrics_list: List[Case2Metrics], output_path: Path):
    """Write case2_metrics.csv"""
    if not metrics_list:
        return

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=asdict(metrics_list[0]).keys())
        writer.writeheader()
        for m in metrics_list:
            writer.writerow(asdict(m))


def write_case2_summary(metrics_list: List[Case2Metrics], output_path: Path):
    """Write case2_summary.txt with comparative analysis"""

    if not metrics_list:
        return

    # Group by subcase
    by_subcase: Dict[str, List[Case2Metrics]] = {}
    for m in metrics_list:
        if m.subcase not in by_subcase:
            by_subcase[m.subcase] = []
        by_subcase[m.subcase].append(m)

    with open(output_path, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("Case 2: Exploration Labs Summary\n")
        f.write("=" * 80 + "\n\n")

        # Case 2.1: Cache Replacement
        if "2.1" in by_subcase:
            f.write("Case 2.1: Cache Replacement Policy Comparison\n")
            f.write("-" * 80 + "\n")
            f.write(f"{'Config':<20} {'Benchmark':<15} {'IPC':>8} {'L2 MR':>8} {'L2 MPKI':>10}\n")
            f.write("-" * 80 + "\n")

            for m in sorted(by_subcase["2.1"], key=lambda x: (x.benchmark, x.ipc), reverse=True):
                f.write(f"{m.config:<20} {m.benchmark:<15} {m.ipc:>8.4f} {m.l2_miss_rate:>8.4f} {m.l2_mpki:>10.2f}\n")

            # Find best config per benchmark
            benchmarks = set(m.benchmark for m in by_subcase["2.1"])
            f.write("\nBest Policy Per Benchmark:\n")
            for bench in sorted(benchmarks):
                bench_metrics = [m for m in by_subcase["2.1"] if m.benchmark == bench]
                best = max(bench_metrics, key=lambda m: m.ipc)
                f.write(f"  {bench}: {best.config} (IPC={best.ipc:.4f})\n")
            f.write("\n")

        # Case 2.2: Branch Prediction
        if "2.2" in by_subcase:
            f.write("Case 2.2: Branch Predictor Comparison\n")
            f.write("-" * 80 + "\n")
            f.write(f"{'Config':<20} {'Benchmark':<15} {'IPC':>8} {'BR MR':>8} {'BR MPKI':>10}\n")
            f.write("-" * 80 + "\n")

            for m in sorted(by_subcase["2.2"], key=lambda x: (x.benchmark, x.ipc), reverse=True):
                f.write(f"{m.config:<20} {m.benchmark:<15} {m.ipc:>8.4f} {m.branch_mispredict_rate:>8.4f} {m.branch_mpki:>10.2f}\n")

            # Find best config per benchmark
            benchmarks = set(m.benchmark for m in by_subcase["2.2"])
            f.write("\nBest Predictor Per Benchmark:\n")
            for bench in sorted(benchmarks):
                bench_metrics = [m for m in by_subcase["2.2"] if m.benchmark == bench]
                best = max(bench_metrics, key=lambda m: m.ipc)
                f.write(f"  {bench}: {best.config} (IPC={best.ipc:.4f}, BR MPKI={best.branch_mpki:.2f})\n")
            f.write("\n")

        # Case 2.3: Prefetcher
        if "2.3" in by_subcase:
            f.write("Case 2.3: Prefetcher Configuration Comparison\n")
            f.write("-" * 80 + "\n")
            f.write(f"{'Config':<20} {'Benchmark':<15} {'IPC':>8} {'L2 MR':>8} {'L2 MPKI':>10}\n")
            f.write("-" * 80 + "\n")

            for m in sorted(by_subcase["2.3"], key=lambda x: (x.benchmark, x.ipc), reverse=True):
                f.write(f"{m.config:<20} {m.benchmark:<15} {m.ipc:>8.4f} {m.l2_miss_rate:>8.4f} {m.l2_mpki:>10.2f}\n")

            # Find best config per benchmark
            benchmarks = set(m.benchmark for m in by_subcase["2.3"])
            f.write("\nBest Prefetcher Per Benchmark:\n")
            for bench in sorted(benchmarks):
                bench_metrics = [m for m in by_subcase["2.3"] if m.benchmark == bench]
                best = max(bench_metrics, key=lambda m: m.ipc)
                f.write(f"  {bench}: {best.config} (IPC={best.ipc:.4f})\n")
            f.write("\n")

        f.write("=" * 80 + "\n")
        f.write("Analysis complete. See case2_metrics.csv for detailed data.\n")
        f.write("=" * 80 + "\n")


def determine_subcase(config: str) -> str:
    """Determine which subcase a config belongs to"""
    if "case2_1" in config or any(x in config for x in ["lru", "fifo", "tree_plru", "drrip"]):
        return "2.1"
    elif "case2_2" in config or any(x in config for x in ["localbp", "bimode", "tage"]):
        return "2.2"
    elif "case2_3" in config or any(x in config for x in ["stride", "prefetch", "ghb"]):
        return "2.3"
    return "unknown"


def run_case2_analysis(stats_dir: Path, configs: List[str], benchmark: str,
                       output_dir: Path) -> List[Case2Metrics]:
    """Run complete Case 2 analysis workflow"""

    metrics_list = []

    # Extract metrics for all configs
    for config_name in configs:
        stats_path = stats_dir / config_name / benchmark / "stats.txt"

        if not stats_path.exists():
            print(f"Warning: Stats not found for {config_name}, skipping")
            continue

        subcase = determine_subcase(config_name)

        metrics = extract_case2_metrics(
            stats_path,
            config=config_name,
            benchmark=benchmark,
            subcase=subcase
        )
        metrics_list.append(metrics)

    # Write outputs
    output_dir.mkdir(parents=True, exist_ok=True)
    write_case2_metrics_csv(metrics_list, output_dir / "case2_metrics.csv")
    write_case2_summary(metrics_list, output_dir / "case2_summary.txt")

    return metrics_list
