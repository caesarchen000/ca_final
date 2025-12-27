#!/usr/bin/env python3
"""
Cache hierarchy analysis module for Case 1.

Extracts PMU counters from gem5 stats, calculates theoretical formulas,
and validates against expected values.
"""

import csv
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict


@dataclass
class CacheMetrics:
    """Raw PMU metrics extracted from gem5 stats.txt"""
    config: str
    benchmark: str

    # Cache sizes
    l1i_size: str
    l1d_size: str
    l2_size: str

    # L1 Instruction Cache
    l1i_accesses: int = 0
    l1i_misses: int = 0
    l1i_hits: int = 0
    l1i_miss_rate: float = 0.0
    l1i_avg_miss_latency: float = 0.0

    # L1 Data Cache
    l1d_accesses: int = 0
    l1d_misses: int = 0
    l1d_hits: int = 0
    l1d_miss_rate: float = 0.0
    l1d_avg_miss_latency: float = 0.0

    # L2 Cache
    l2_accesses: int = 0
    l2_misses: int = 0
    l2_hits: int = 0
    l2_miss_rate: float = 0.0
    l2_avg_miss_latency: float = 0.0

    # Performance
    ipc: float = 0.0
    sim_seconds: float = 0.0
    num_cycles: int = 0
    sim_ticks: int = 0


@dataclass
class CacheAnalysis:
    """Calculated formulas and validation results"""
    config: str
    benchmark: str

    # Miss rate verification
    miss_rate_l1i_calc: float = 0.0
    miss_rate_l1d_calc: float = 0.0
    miss_rate_l2_calc: float = 0.0
    miss_rate_verification: str = "N/A"

    # AMAT calculations
    amat_l1i: float = 0.0
    amat_l1d: float = 0.0
    amat_l2: float = 0.0
    amat_overall: float = 0.0

    # Speedup analysis
    speedup_vs_nocache: float = 1.0
    speedup_theoretical: float = 1.0
    speedup_error_pct: float = 0.0

    # Validation
    validation_status: str = "UNKNOWN"
    error_summary: str = ""


def extract_stat(stats_content: str, pattern: str) -> Optional[float]:
    """Extract a single stat value using regex pattern."""
    match = re.search(pattern, stats_content, re.MULTILINE)
    if match:
        try:
            return float(match.group(1))
        except (ValueError, IndexError):
            return None
    return None


def extract_cache_metrics(stats_path: Path, config: str, benchmark: str,
                          l1i_size: str, l1d_size: str, l2_size: str) -> CacheMetrics:
    """Extract cache-related PMU counters from stats.txt"""

    if not stats_path.exists():
        raise FileNotFoundError(f"Stats file not found: {stats_path}")

    with open(stats_path, 'r') as f:
        content = f.read()

    metrics = CacheMetrics(
        config=config,
        benchmark=benchmark,
        l1i_size=l1i_size,
        l1d_size=l1d_size,
        l2_size=l2_size
    )

    # Extract L1 Instruction Cache stats
    metrics.l1i_accesses = int(extract_stat(content, r'system\.cpu\.icache\.demandAccesses::total\s+(\d+)') or 0)
    metrics.l1i_misses = int(extract_stat(content, r'system\.cpu\.icache\.demandMisses::total\s+(\d+)') or 0)
    metrics.l1i_hits = int(extract_stat(content, r'system\.cpu\.icache\.demandHits::total\s+(\d+)') or 0)
    metrics.l1i_miss_rate = extract_stat(content, r'system\.cpu\.icache\.demandMissRate::total\s+([\d.]+)') or 0.0
    metrics.l1i_avg_miss_latency = extract_stat(content, r'system\.cpu\.icache\.demandAvgMissLatency::total\s+([\d.]+)') or 0.0

    # Extract L1 Data Cache stats
    metrics.l1d_accesses = int(extract_stat(content, r'system\.cpu\.dcache\.demandAccesses::total\s+(\d+)') or 0)
    metrics.l1d_misses = int(extract_stat(content, r'system\.cpu\.dcache\.demandMisses::total\s+(\d+)') or 0)
    metrics.l1d_hits = int(extract_stat(content, r'system\.cpu\.dcache\.demandHits::total\s+(\d+)') or 0)
    metrics.l1d_miss_rate = extract_stat(content, r'system\.cpu\.dcache\.demandMissRate::total\s+([\d.]+)') or 0.0
    metrics.l1d_avg_miss_latency = extract_stat(content, r'system\.cpu\.dcache\.demandAvgMissLatency::total\s+([\d.]+)') or 0.0

    # Extract L2 Cache stats (if exists)
    metrics.l2_accesses = int(extract_stat(content, r'system\.l2\.demandAccesses::total\s+(\d+)') or 0)
    metrics.l2_misses = int(extract_stat(content, r'system\.l2\.demandMisses::total\s+(\d+)') or 0)
    metrics.l2_hits = int(extract_stat(content, r'system\.l2\.demandHits::total\s+(\d+)') or 0)
    metrics.l2_miss_rate = extract_stat(content, r'system\.l2\.demandMissRate::total\s+([\d.]+)') or 0.0
    metrics.l2_avg_miss_latency = extract_stat(content, r'system\.l2\.demandAvgMissLatency::total\s+([\d.]+)') or 0.0

    # Extract performance metrics
    metrics.ipc = extract_stat(content, r'system\.cpu\.ipc\s+([\d.]+)') or 0.0
    metrics.sim_seconds = extract_stat(content, r'simSeconds\s+([\d.]+)') or 0.0
    metrics.num_cycles = int(extract_stat(content, r'system\.cpu\.numCycles\s+(\d+)') or 0)
    metrics.sim_ticks = int(extract_stat(content, r'simTicks\s+(\d+)') or 0)

    return metrics


def get_clock_period_ticks(stats_path: Path) -> int:
    """Extract clock period in ticks from stats.txt

    Returns clock period in ticks (typically 1000 for 1GHz clock)
    """
    with open(stats_path, 'r') as f:
        content = f.read()

    clock_period = extract_stat(content, r'system\.clk_domain\.clock\s+(\d+)')
    return int(clock_period) if clock_period else 1000  # Default to 1000 if not found


def calculate_miss_rate(misses: int, accesses: int) -> float:
    """Calculate miss rate = misses / accesses"""
    if accesses == 0:
        return 0.0
    return misses / accesses


def calculate_amat(hit_time: float, miss_rate: float, miss_penalty: float) -> float:
    """Calculate Average Memory Access Time

    AMAT = Hit Time + (Miss Rate × Miss Penalty)
    """
    return hit_time + (miss_rate * miss_penalty)


def calculate_speedup(baseline_ipc: float, current_ipc: float) -> float:
    """Calculate speedup = current_ipc / baseline_ipc"""
    if baseline_ipc == 0:
        return 1.0
    return current_ipc / baseline_ipc


def analyze_cache_metrics(metrics: CacheMetrics, baseline_ipc: float = None) -> CacheAnalysis:
    """Perform formula calculations and validation"""

    analysis = CacheAnalysis(
        config=metrics.config,
        benchmark=metrics.benchmark
    )

    # Calculate miss rates
    analysis.miss_rate_l1i_calc = calculate_miss_rate(metrics.l1i_misses, metrics.l1i_accesses)
    analysis.miss_rate_l1d_calc = calculate_miss_rate(metrics.l1d_misses, metrics.l1d_accesses)
    analysis.miss_rate_l2_calc = calculate_miss_rate(metrics.l2_misses, metrics.l2_accesses)

    # Verify miss rates against gem5 reported values
    errors = []
    l1i_error = abs(analysis.miss_rate_l1i_calc - metrics.l1i_miss_rate)
    l1d_error = abs(analysis.miss_rate_l1d_calc - metrics.l1d_miss_rate)
    l2_error = abs(analysis.miss_rate_l2_calc - metrics.l2_miss_rate)

    if l1i_error > 0.001 and metrics.l1i_accesses > 0:
        errors.append(f"L1I miss rate error: {l1i_error:.4f}")
    if l1d_error > 0.001 and metrics.l1d_accesses > 0:
        errors.append(f"L1D miss rate error: {l1d_error:.4f}")
    if l2_error > 0.001 and metrics.l2_accesses > 0:
        errors.append(f"L2 miss rate error: {l2_error:.4f}")

    analysis.miss_rate_verification = "PASS" if not errors else "FAIL"

    # Calculate AMAT using actual gem5 latencies
    # Note: gem5 reports latencies in ticks, need to convert to cycles
    # Clock period is typically 1000 ticks/cycle for 1GHz clock
    L1_HIT_TIME_CYCLES = 1.0  # L1 cache hit takes 1 cycle

    # gem5's avgMissLatency already includes the full miss handling time
    # (e.g., L1 miss penalty includes L2 access + potential memory access)
    # So we don't need to manually compute hierarchical AMAT

    # Convert latencies from ticks to cycles (assume 1000 ticks per cycle)
    CLOCK_PERIOD_TICKS = 1000.0

    l1i_miss_penalty_cycles = metrics.l1i_avg_miss_latency / CLOCK_PERIOD_TICKS
    l1d_miss_penalty_cycles = metrics.l1d_avg_miss_latency / CLOCK_PERIOD_TICKS
    l2_miss_penalty_cycles = metrics.l2_avg_miss_latency / CLOCK_PERIOD_TICKS

    # L1I AMAT = Hit Time + (Miss Rate × Miss Penalty)
    analysis.amat_l1i = calculate_amat(L1_HIT_TIME_CYCLES, analysis.miss_rate_l1i_calc, l1i_miss_penalty_cycles)

    # L1D AMAT = Hit Time + (Miss Rate × Miss Penalty)
    analysis.amat_l1d = calculate_amat(L1_HIT_TIME_CYCLES, analysis.miss_rate_l1d_calc, l1d_miss_penalty_cycles)

    # L2 AMAT (if exists) - this is the average access time seen by L1 misses
    if metrics.l2_size != "0" and metrics.l2_accesses > 0:
        # For L2, we use 10 cycles as hit time (typical L2 latency)
        L2_HIT_TIME_CYCLES = 10.0
        analysis.amat_l2 = calculate_amat(L2_HIT_TIME_CYCLES, analysis.miss_rate_l2_calc, l2_miss_penalty_cycles)
    else:
        analysis.amat_l2 = 0.0

    # Overall AMAT (weighted average of I and D)
    # Weight by actual access counts instead of arbitrary 70/30
    total_accesses = metrics.l1i_accesses + metrics.l1d_accesses
    if total_accesses > 0:
        weight_i = metrics.l1i_accesses / total_accesses
        weight_d = metrics.l1d_accesses / total_accesses
        analysis.amat_overall = weight_i * analysis.amat_l1i + weight_d * analysis.amat_l1d
    else:
        analysis.amat_overall = 0.0

    # Calculate speedup
    if baseline_ipc is not None:
        analysis.speedup_vs_nocache = calculate_speedup(baseline_ipc, metrics.ipc)

        # Theoretical speedup based on AMAT reduction (rough approximation)
        # Speedup ≈ AMAT_baseline / AMAT_current
        # This is a simplification; actual speedup depends on memory-boundedness
        analysis.speedup_theoretical = analysis.speedup_vs_nocache  # Placeholder for now

        error = abs(analysis.speedup_vs_nocache - analysis.speedup_theoretical)
        analysis.speedup_error_pct = (error / analysis.speedup_vs_nocache * 100) if analysis.speedup_vs_nocache > 0 else 0.0

    # Validation status
    if errors:
        analysis.validation_status = "FAIL"
        analysis.error_summary = "; ".join(errors)
    else:
        analysis.validation_status = "PASS"
        analysis.error_summary = ""

    return analysis


def write_metrics_csv(metrics_list: List[CacheMetrics], output_path: Path):
    """Write cache_metrics.csv"""
    if not metrics_list:
        return

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=asdict(metrics_list[0]).keys())
        writer.writeheader()
        for m in metrics_list:
            writer.writerow(asdict(m))


def write_analysis_csv(analysis_list: List[CacheAnalysis], output_path: Path):
    """Write cache_analysis.csv"""
    if not analysis_list:
        return

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=asdict(analysis_list[0]).keys())
        writer.writeheader()
        for a in analysis_list:
            writer.writerow(asdict(a))


def write_summary_report(metrics_list: List[CacheMetrics],
                        analysis_list: List[CacheAnalysis],
                        output_path: Path):
    """Write cache_summary.txt"""

    if not metrics_list or not analysis_list:
        return

    benchmark = metrics_list[0].benchmark
    num_configs = len(metrics_list)

    # Find nocache and best config
    nocache_ipc = next((m.ipc for m in metrics_list if m.config == "nocache"), None)
    best_config = max(metrics_list, key=lambda m: m.ipc)

    # Count validations
    passed = sum(1 for a in analysis_list if a.validation_status == "PASS")
    failed = num_configs - passed

    with open(output_path, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("Cache Hierarchy Analysis Summary\n")
        f.write("=" * 70 + "\n\n")

        f.write(f"Benchmark: {benchmark}\n")
        f.write(f"Configs analyzed: {num_configs}\n")
        f.write(f"Validations: {passed} PASS, {failed} FAIL\n\n")

        if nocache_ipc and best_config:
            speedup = best_config.ipc / nocache_ipc if nocache_ipc > 0 else 0
            f.write("Key Findings:\n")
            f.write(f"  1. Baseline (nocache) IPC: {nocache_ipc:.4f}\n")
            f.write(f"  2. Best config: {best_config.config}\n")
            f.write(f"     - IPC: {best_config.ipc:.4f}\n")
            f.write(f"     - Speedup: {speedup:.2f}x\n")
            f.write(f"     - L1I miss rate: {best_config.l1i_miss_rate:.4f}\n")
            f.write(f"     - L1D miss rate: {best_config.l1d_miss_rate:.4f}\n")
            if best_config.l2_size != "0":
                f.write(f"     - L2 miss rate: {best_config.l2_miss_rate:.4f}\n")
            f.write("\n")

        f.write("Configuration Details:\n")
        f.write("-" * 70 + "\n")
        f.write(f"{'Config':<15} {'IPC':>8} {'L1I MR':>8} {'L1D MR':>8} {'L2 MR':>8} {'Status':>10}\n")
        f.write("-" * 70 + "\n")

        for m, a in zip(metrics_list, analysis_list):
            l2_mr = f"{m.l2_miss_rate:.4f}" if m.l2_size != "0" else "N/A"
            f.write(f"{m.config:<15} {m.ipc:>8.4f} {m.l1i_miss_rate:>8.4f} {m.l1d_miss_rate:>8.4f} {l2_mr:>8} {a.validation_status:>10}\n")

        f.write("\n")
        f.write("=" * 70 + "\n")
        f.write("Analysis complete. See cache_metrics.csv and cache_analysis.csv for details.\n")
        f.write("=" * 70 + "\n")


def run_cache_analysis(stats_dir: Path, configs: List[Dict], benchmark: str,
                      output_dir: Path) -> Tuple[List[CacheMetrics], List[CacheAnalysis]]:
    """Run complete cache analysis workflow"""

    metrics_list = []
    analysis_list = []
    baseline_ipc = None

    # Extract metrics for all configs
    for cfg in configs:
        config_name = cfg["name"]
        stats_path = stats_dir / config_name / benchmark / "stats.txt"

        if not stats_path.exists():
            print(f"Warning: Stats not found for {config_name}, skipping")
            continue

        metrics = extract_cache_metrics(
            stats_path,
            config=config_name,
            benchmark=benchmark,
            l1i_size=cfg.get("l1i_size", "0"),
            l1d_size=cfg.get("l1d_size", "0"),
            l2_size=cfg.get("l2_size", "0")
        )
        metrics_list.append(metrics)

        # Save baseline IPC
        if config_name == "nocache":
            baseline_ipc = metrics.ipc

    # Analyze all configs
    for metrics in metrics_list:
        analysis = analyze_cache_metrics(metrics, baseline_ipc)
        analysis_list.append(analysis)

    # Write outputs
    output_dir.mkdir(parents=True, exist_ok=True)
    write_metrics_csv(metrics_list, output_dir / "cache_metrics.csv")
    write_analysis_csv(analysis_list, output_dir / "cache_analysis.csv")
    write_summary_report(metrics_list, analysis_list, output_dir / "cache_summary.txt")

    return metrics_list, analysis_list
