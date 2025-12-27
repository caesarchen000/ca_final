#!/usr/bin/env python3
"""
formace-lab - Unified testing framework for gem5 microarchitecture optimizations

Implements the CLI layout described in README.md, including the suite command
family that orchestrates cache, branch, and prefetcher experiments.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# Setup paths
SCRIPT_DIR = Path(__file__).parent.resolve()
# Default GEM5_HOME to parent directory if not set
GEM5_HOME = os.environ.get("GEM5_HOME", str(SCRIPT_DIR.parent))

# Import local modules
sys.path.insert(0, str(SCRIPT_DIR / "src"))
from runpaths import ensure_subdir, get_run_id
from simulator import run_gem5
from metrics import main as metrics_main, parse_stats, collect_metrics

RUN_ID = get_run_id()
CPU_TYPE = "O3CPU"
MEM_SIZE = "1GB"

# Benchmark definitions (ordered: fast → slow for batch testing)
BENCHMARKS: Dict[str, str] = {
    # Algorithm microbenchmarks (fast, simple)
    "mm": "benchmarks/algo/mm.riscv",
    "vvadd": "benchmarks/algo/vvadd.riscv",
    "qsort": "benchmarks/algo/qsort.riscv",
    "stream": "benchmarks/algo/stream.riscv",
    "towers": "benchmarks/algo/towers.riscv",
    "pointer_chase": "benchmarks/algo/pointer_chase.riscv",
    "binary_search": "benchmarks/algo/binary_search.riscv",
    # Industry-standard benchmarks (slower, many iterations)
    "dhrystone": "benchmarks/dhrystone/dhrystone.riscv",
    "coremark": "benchmarks/coremark/coremark.exe",
    # Smoky target (alias for dhrystone build placed under benchmarks/smoky)
    "smoky": "benchmarks/smoky/dhrystone.riscv",
    # Synthetic microbenchmarks for branch prediction
    "branch_corr": "benchmarks/synthetic/branch-patterns/branch_corr.riscv",
    "branch_bias": "benchmarks/synthetic/branch-patterns/branch_bias.riscv",
    # Synthetic microbenchmark for cache replacement policy
    "cache_thrash": "benchmarks/synthetic/replacement-policy/cache_thrash.riscv",
}

BENCHMARK_GROUPS: Dict[str, Tuple[str, ...]] = {
    "heuristic": ("mm", "vvadd", "qsort", "stream", "towers"),
    "microbench": ("towers", "pointer_chase", "binary_search"),
}

CACHE_POLICY_CHOICES = {
    "lru": {
        "label": "LRU",
        "l2_rp_type": None,
    },
    "fifo": {
        "label": "FIFO",
        "l2_rp_type": "FIFORP",
    },
    "treeplru": {
        "label": "TreePLRU",
        "l2_rp_type": "TreePLRURP",
    },
}

BRANCH_PREDICTOR_CHOICES = {
    "localbp": {
        "label": "LocalBP",
        "bp_type": "LocalBP",
    },
    "bimodebp": {
        "label": "BiModeBP",
        "bp_type": "BiModeBP",
    },
    "tage_lite": {
        "label": "TAGE_LITE",
        "bp_type": "TAGE_LITE",
    },
}

PREFETCHER_CHOICES = {
    "strideprefetcher": {
        "label": "StridePrefetcher",
        "l2_hwp_type": "StridePrefetcher",
        "supports_degree": True,
    },
    "ampmpprefetcher": {
        "label": "AMPMPrefetcher",
        "l2_hwp_type": "AMPMPrefetcher",
        "supports_degree": False,
    },
    "bopprefetcher": {
        "label": "BOPPrefetcher",
        "l2_hwp_type": "BOPPrefetcher",
        "supports_degree": False,
    },
}

GHB_PREFETCHER_CHOICES = {
    "baselinestride": {
        "label": "BaselineStride",
        "l2_hwp_type": "StridePrefetcher",
        "supports_degree": True,
    },
    "ghb_litestudent": {
        "label": "GHB_LiteStudent",
        "l2_hwp_type": "GHBPrefetcher",
        "supports_degree": False,
    },
}

CASE_OUTPUT_ROOTS = {
    "case1-1": "output/case1",
    "cache-size": "output/case1",
    "cache-policy": "output/case1",
    "branch": "output/case2",
    "prefetch-upstream": "output/case3",
    "prefetch-ghb": "output/case3",
}


@dataclass
class Experiment:
    """Definition for a benchmark/config pair launched by suite commands."""

    bench_name: str
    binary: Path
    label: str
    gem5_kwargs: Dict[str, object] = field(default_factory=dict)
    metadata: Dict[str, object] = field(default_factory=dict)


def slugify(value: str) -> str:
    """Turn arbitrary text into a filesystem-friendly slug."""
    clean = re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_")
    return clean.lower() or "default"


def check_venv():
    """Check if we're in venv, if not suggest activation."""
    in_venv = hasattr(sys, "real_prefix") or (
        hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
    )

    venv_path = SCRIPT_DIR / "venv"

    if not in_venv and venv_path.exists():
        print("WARNING: Virtual environment exists but not activated", file=sys.stderr)
        print(f"Activate with: source {venv_path}/bin/activate", file=sys.stderr)
        print()
    elif not venv_path.exists():
        print("NOTE: No virtual environment found", file=sys.stderr)
        print("You can create one with: python3 -m venv venv", file=sys.stderr)
        print("This project has no external dependencies, so venv is optional.", file=sys.stderr)
        print()


def check_gem5_home(require_binary: bool = True) -> Path:
    """Verify GEM5_HOME is set and valid.

    Args:
        require_binary: If True, also check that gem5.fast exists (default: True)
    """
    if not GEM5_HOME:
        print("ERROR: GEM5_HOME environment variable not set", file=sys.stderr)
        print("Please set: export GEM5_HOME=/path/to/gem5", file=sys.stderr)
        sys.exit(1)

    gem5_path = Path(GEM5_HOME)

    if require_binary:
        gem5_bin = gem5_path / "build" / "RISCV" / "gem5.fast"
        if not gem5_bin.exists():
            print(f"ERROR: gem5 binary not found at {gem5_bin}", file=sys.stderr)
            sys.exit(1)

    return gem5_path


def extract_metrics_from_stats(stats_path: Path) -> dict:
    """Extract metrics from a stats.txt file."""
    try:
        # If path is a directory, look for stats.txt inside
        if stats_path.is_dir():
            stats_file = stats_path / "stats.txt"
        else:
            stats_file = stats_path

        if not stats_file.exists():
            return {}

        stats = parse_stats(stats_file)
        return collect_metrics(stats)
    except Exception:
        return {}


def extract_stat(stats_path: Path, pattern: str) -> str:
    """Extract a specific stat matching a regex pattern from stats.txt."""
    try:
        # If path is a directory, look for stats.txt inside
        if stats_path.is_dir():
            stats_file = stats_path / "stats.txt"
        else:
            stats_file = stats_path

        if not stats_file.exists():
            return "N/A"

        with stats_file.open() as f:
            for line in f:
                if re.match(pattern, line):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
        return "N/A"
    except Exception:
        return "N/A"


def resolve_optional_path(path_str: Optional[str]) -> Optional[str]:
    if not path_str:
        return None
    path = Path(path_str)
    if not path.is_absolute():
        path = (SCRIPT_DIR / path).resolve()
    return str(path)


def resolve_programs(names: Sequence[str]) -> List[Tuple[str, Path]]:
    """Resolve benchmark/workload names into concrete binaries."""
    if not names:
        raise ValueError("No benchmarks/workloads specified.")

    resolved: List[Tuple[str, Path]] = []
    for entry in names:
        if not entry:
            continue
        key = entry.strip()
        group = BENCHMARK_GROUPS.get(key.lower())
        if group:
            resolved.extend(resolve_programs(group))
            continue
        bench_path = BENCHMARKS.get(key)
        if bench_path is None:
            raise ValueError(f"Unknown benchmark/workload '{key}'.")
        abs_path = (SCRIPT_DIR / bench_path).resolve()
        if not abs_path.exists():
            raise FileNotFoundError(f"Benchmark binary not found: {abs_path}")
        resolved.append((key, abs_path))

    seen = set()
    unique: List[Tuple[str, Path]] = []
    for name, path in resolved:
        if name in seen:
            continue
        seen.add(name)
        unique.append((name, path))
    return unique


def resolve_output_dir(case_name: str, override: Optional[str]) -> Path:
    """Build the output directory for a suite run."""
    if override:
        out_path = Path(override)
        if not out_path.is_absolute():
            out_path = (SCRIPT_DIR / out_path).resolve()
    else:
        root = CASE_OUTPUT_ROOTS.get(case_name, "logs_misc")
        out_path = (SCRIPT_DIR / root / RUN_ID).resolve()
    out_path.mkdir(parents=True, exist_ok=True)
    return out_path


def prefix_metrics(prefix: str, stats: Dict[str, float]) -> Dict[str, Optional[float]]:
    """Prefix the collected metrics for CSV/summary output."""
    metrics = collect_metrics(stats)
    return {f"{prefix}_{key}": value for key, value in metrics.items()}


def write_results_csv(rows: List[Dict[str, object]], output_file: Path) -> None:
    """Serialize suite results as CSV."""
    if not rows:
        return
    fieldnames = sorted({key for row in rows for key in row.keys()})
    with output_file.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            serialized = {}
            for key in fieldnames:
                value = row.get(key, "")
                if value is None:
                    serialized[key] = ""
                else:
                    serialized[key] = value
            writer.writerow(serialized)


def format_value(value: Optional[float]) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        if abs(value) >= 1000:
            return f"{value:.2e}"
        if abs(value) >= 1:
            return f"{value:.3f}"
        return f"{value:.4f}"
    return str(value)


def print_suite_summary(rows: List[Dict[str, object]]) -> None:
    """Print a quick human-readable summary after a suite run."""
    if not rows:
        return
    print()
    print("Suite summary (caches)")
    print("-" * 72)
    header = f"{'Benchmark':<18}{'Config':<22}{'IPC':<10}{'L1D MPKI':<12}{'L2 MPKI':<12}{'Branch MPKI':<12}"
    print(header)
    print("-" * len(header))
    for row in rows:
        print(
            f"{row.get('benchmark','-'):<18}"
            f"{row.get('config','-'):<22}"
            f"{format_value(row.get('caches_ipc')):<10}"
            f"{format_value(row.get('caches_l1d_mpki')):<12}"
            f"{format_value(row.get('caches_l2_mpki')):<12}"
            f"{format_value(row.get('caches_branch_mpki')):<12}"
        )
    print()


def execute_experiment(exp: Experiment, output_dir: Path, run_nocache: bool = True) -> Dict[str, object]:
    """Run nocache/caches for a benchmark and return collected metrics.

    Args:
        exp: Experiment configuration
        output_dir: Output directory
        run_nocache: If True, run both nocache and caches; if False, only run caches
    """
    bench_dir = output_dir / exp.bench_name / exp.label
    bench_dir.mkdir(parents=True, exist_ok=True)

    cases = ("nocache", "caches") if run_nocache else ("caches",)
    for case in cases:
        ret = run_gem5(
            prog=str(exp.binary),
            output_dir=bench_dir,
            case=case,
            cpu=CPU_TYPE,
            mem=MEM_SIZE,
            gem5_home=GEM5_HOME,
            **exp.gem5_kwargs,
        )
        if ret != 0:
            raise RuntimeError(f"gem5 returned {ret} for {exp.bench_name} ({exp.label}) [{case}]")

    row: Dict[str, object] = {
        "benchmark": exp.bench_name,
        "config": exp.label,
    }
    row.update(exp.metadata)

    if run_nocache:
        nocache_stats = parse_stats(bench_dir / "nocache" / "stats.txt")
        row.update(prefix_metrics("nocache", nocache_stats))

    caches_stats = parse_stats(bench_dir / "caches" / "stats.txt")
    row.update(prefix_metrics("caches", caches_stats))

    if run_nocache:
        ipc_nocache = row.get("nocache_ipc")
        ipc_caches = row.get("caches_ipc")
        if isinstance(ipc_nocache, float) and ipc_nocache != 0 and isinstance(ipc_caches, float):
            row["ipc_speedup"] = ipc_caches / ipc_nocache

    return row


def run_suite(case_name: str, experiments: Sequence[Experiment], output_dir: Path, run_nocache: bool = True) -> int:
    """Execute a list of experiments and write standard artifacts.

    Args:
        case_name: Name of the case/suite
        experiments: List of experiments to run
        output_dir: Output directory
        run_nocache: If True, run both nocache and caches; if False, only run caches
    """
    check_gem5_home()
    if not experiments:
        print("ERROR: Nothing to run for this suite.", file=sys.stderr)
        return 1

    print(f"\nRunning {case_name} suite with {len(experiments)} experiment(s)")
    print(f"Output directory: {output_dir}")
    if not run_nocache:
        print("(Skipping nocache runs for performance)")

    rows: List[Dict[str, object]] = []
    for exp in experiments:
        try:
            row = execute_experiment(exp, output_dir, run_nocache=run_nocache)
            row["case"] = case_name
            rows.append(row)
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    write_results_csv(rows, output_dir / "all_results.csv")
    # Note: PMU summary removed for student assignments
    # Students must extract metrics from stats.txt themselves
    return 0


def run_example(case_name: str, experiments: Sequence[Experiment], output_dir: Path, run_nocache: bool = True) -> int:
    """Execute example experiments with full PMU summary (for teaching purposes).

    Args:
        case_name: Name of the case/suite
        experiments: List of experiments to run
        output_dir: Output directory
        run_nocache: If True, run both nocache and caches; if False, only run caches
    """
    check_gem5_home()
    if not experiments:
        print("ERROR: Nothing to run for this example.", file=sys.stderr)
        return 1

    print(f"\nRunning {case_name} example with {len(experiments)} experiment(s)")
    print(f"Output directory: {output_dir}")
    if not run_nocache:
        print("(Skipping nocache runs for performance)")

    rows: List[Dict[str, object]] = []
    for exp in experiments:
        try:
            row = execute_experiment(exp, output_dir, run_nocache=run_nocache)
            row["case"] = case_name
            rows.append(row)
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    write_results_csv(rows, output_dir / "all_results.csv")
    print_suite_summary(rows)  # Show summary for teaching
    print(f"\nall_results.csv written to {output_dir / 'all_results.csv'}")
    print("\nNote: This example shows the PMU metrics summary.")
    print("For homework assignments, you must extract these metrics from stats.txt yourself.")
    return 0


# ============================================================================
# Example command implementations (with PMU summary for teaching)
# ============================================================================


def example_cache_size(args: argparse.Namespace) -> int:
    """Example: Cache size sweep with PMU summary displayed."""
    try:
        benchmarks = resolve_programs(args.benchmarks)
    except (ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    sweep_specs: List[Tuple[str, str, str]] = []
    for size in args.l1d_sizes or []:
        sweep_specs.append(("l1d", size, args.l2_size))
    for size in args.l2_sizes or []:
        sweep_specs.append(("l2", args.l1d_size, size))
    if not sweep_specs:
        sweep_specs.append(("fixed", args.l1d_size, args.l2_size))

    experiments: List[Experiment] = []
    for bench_name, bench_path in benchmarks:
        for sweep_kind, l1d_value, l2_value in sweep_specs:
            if sweep_kind == "l1d":
                label = f"l1d_{slugify(l1d_value)}"
            elif sweep_kind == "l2":
                label = f"l2_{slugify(l2_value)}"
            else:
                label = "baseline"

            experiments.append(
                Experiment(
                    bench_name=bench_name,
                    binary=bench_path,
                    label=label,
                    gem5_kwargs={
                        "l1i_size": args.l1i_size,
                        "l1d_size": l1d_value,
                        "l2_size": l2_value,
                    },
                    metadata={
                        "sweep_target": sweep_kind,
                        "l1d_size": l1d_value,
                        "l2_size": l2_value,
                    },
                )
            )

    output_dir = resolve_output_dir("case1-1", args.out)
    return run_example("Case 1.1 (L1 Cache Size Sweep - Example)", experiments, output_dir, run_nocache=True)


# ============================================================================
# Suite command implementations
# ============================================================================


def suite_cache_size(args: argparse.Namespace) -> int:
    try:
        benchmarks = resolve_programs(args.benchmarks)
    except (ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    sweep_specs: List[Tuple[str, str, str]] = []
    for size in args.l1d_sizes or []:
        sweep_specs.append(("l1d", size, args.l2_size))
    for size in args.l2_sizes or []:
        sweep_specs.append(("l2", args.l1d_size, size))
    if not sweep_specs:
        sweep_specs.append(("fixed", args.l1d_size, args.l2_size))

    experiments: List[Experiment] = []
    for bench_name, bench_path in benchmarks:
        for sweep_kind, l1d_value, l2_value in sweep_specs:
            if sweep_kind == "l1d":
                label = f"l1d_{slugify(l1d_value)}"
            elif sweep_kind == "l2":
                label = f"l2_{slugify(l2_value)}"
            else:
                label = "baseline"

            experiments.append(
                Experiment(
                    bench_name=bench_name,
                    binary=bench_path,
                    label=label,
                    gem5_kwargs={
                        "l1i_size": args.l1i_size,
                        "l1d_size": l1d_value,
                        "l2_size": l2_value,
                    },
                    metadata={
                        "sweep_target": sweep_kind,
                        "l1d_size": l1d_value,
                        "l2_size": l2_value,
                    },
                )
            )

    output_dir = resolve_output_dir("cache-size", args.out)
    return run_suite("cache-size", experiments, output_dir, run_nocache=True)


def suite_cache_policy(args: argparse.Namespace) -> int:
    try:
        benchmarks = resolve_programs(args.benchmarks)
    except (ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    policies = []
    for policy_name in args.cache_policy:
        key = policy_name.lower()
        if key not in CACHE_POLICY_CHOICES:
            print(f"ERROR: Unknown cache policy '{policy_name}'", file=sys.stderr)
            return 1
        policies.append(CACHE_POLICY_CHOICES[key])

    experiments: List[Experiment] = []
    for bench_name, bench_path in benchmarks:
        for policy in policies:
            label = slugify(policy["label"])
            experiments.append(
                Experiment(
                    bench_name=bench_name,
                    binary=bench_path,
                    label=f"policy_{label}",
                    gem5_kwargs={
                        "l1i_size": args.l1i_size,
                        "l1d_size": args.l1d_size,
                        "l2_size": args.l2_size,
                        "l2_rp_type": policy["l2_rp_type"],
                    },
                    metadata={
                        "policy": policy["label"],
                        "l1d_size": args.l1d_size,
                        "l2_size": args.l2_size,
                    },
                )
            )

    output_dir = resolve_output_dir("cache-policy", args.out)
    return run_suite("cache-policy", experiments, output_dir, run_nocache=True)


def suite_branch(args: argparse.Namespace) -> int:
    try:
        benchmarks = resolve_programs(args.benchmarks)
    except (ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    predictors = []
    for name in args.predictors:
        key = name.lower()
        if key not in BRANCH_PREDICTOR_CHOICES:
            print(f"ERROR: Unknown predictor '{name}'", file=sys.stderr)
            return 1
        predictors.append(BRANCH_PREDICTOR_CHOICES[key])

    experiments: List[Experiment] = []
    for bench_name, bench_path in benchmarks:
        for predictor in predictors:
            label = slugify(predictor["label"])
            experiments.append(
                Experiment(
                    bench_name=bench_name,
                    binary=bench_path,
                    label=f"bp_{label}",
                    gem5_kwargs={
                        "l1i_size": args.l1i_size,
                        "l1d_size": args.l1d_size,
                        "l2_size": args.l2_size,
                        "bp_type": predictor["bp_type"],
                    },
                    metadata={"predictor": predictor["label"]},
                )
            )

    output_dir = resolve_output_dir("branch", args.out)
    return run_suite("branch", experiments, output_dir, run_nocache=False)


def suite_prefetch_upstream(args: argparse.Namespace) -> int:
    try:
        benchmarks = resolve_programs(args.benchmarks)
    except (ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    prefetchers = []
    for name in args.prefetchers:
        key = name.lower()
        if key not in PREFETCHER_CHOICES:
            print(f"ERROR: Unknown prefetcher '{name}'", file=sys.stderr)
            return 1
        prefetchers.append(PREFETCHER_CHOICES[key])

    experiments: List[Experiment] = []
    for bench_name, bench_path in benchmarks:
        for prefetcher in prefetchers:
            degrees = args.stride_degree if prefetcher["supports_degree"] else [None]
            for degree in degrees:
                suffix = f"_deg{degree}" if degree is not None else ""
                label = slugify(prefetcher["label"] + suffix)
                kwargs = {
                    "l1i_size": args.l1i_size,
                    "l1d_size": args.l1d_size,
                    "l2_size": args.l2_size,
                    "l2_hwp_type": prefetcher["l2_hwp_type"],
                }
                if degree is not None:
                    kwargs["stride_degree"] = degree
                experiments.append(
                    Experiment(
                        bench_name=bench_name,
                        binary=bench_path,
                        label=f"pref_{label}",
                        gem5_kwargs=kwargs,
                        metadata={
                            "prefetcher": prefetcher["label"],
                            "stride_degree": degree,
                        },
                    )
                )

    output_dir = resolve_output_dir("prefetch-upstream", args.out)
    return run_suite("prefetch-upstream", experiments, output_dir, run_nocache=False)


def suite_prefetch_ghb(args: argparse.Namespace) -> int:
    """Run Case 3.2: GHB prefetcher comparison with fixed configuration."""
    gem5_root = check_gem5_home(require_binary=True)

    # Fixed configuration for Case 3.2
    FIXED_BENCHMARKS = ["stream", "vvadd", "qsort", "towers", "mm", "binary_search", "pointer_chase"]
    FIXED_L1I_SIZE = "32kB"
    FIXED_L1D_SIZE = "32kB"
    FIXED_L2_SIZE = "256kB"
    FIXED_STRIDE_DEGREE = 1

    print("="*80)
    print("Case 3.2: GHB Prefetcher Performance Analysis")
    print("="*80)
    print(f"Configuration: L1I={FIXED_L1I_SIZE}, L1D={FIXED_L1D_SIZE}, L2={FIXED_L2_SIZE}")
    print(f"Benchmarks: {', '.join(FIXED_BENCHMARKS)}")
    print(f"Comparing: Baseline Stride (degree={FIXED_STRIDE_DEGREE}) vs GHB_LiteStudent")
    print("="*80)
    print()

    # Resolve fixed benchmarks
    try:
        benchmarks = resolve_programs(FIXED_BENCHMARKS)
    except (ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    # Fixed prefetchers: BaselineStride and GHB_LiteStudent
    prefetchers = [
        GHB_PREFETCHER_CHOICES["baselinestride"],
        GHB_PREFETCHER_CHOICES["ghb_litestudent"],
    ]

    # Build experiments
    experiments: List[Experiment] = []
    for bench_name, bench_path in benchmarks:
        for prefetcher in prefetchers:
            kwargs = {
                "l1i_size": FIXED_L1I_SIZE,
                "l1d_size": FIXED_L1D_SIZE,
                "l2_size": FIXED_L2_SIZE,
                "l2_hwp_type": prefetcher["l2_hwp_type"],
            }
            # Only add degree for stride prefetcher
            if prefetcher["supports_degree"]:
                kwargs["stride_degree"] = FIXED_STRIDE_DEGREE

            label = f"pref_{slugify(prefetcher['label'])}"
            experiments.append(
                Experiment(
                    bench_name=bench_name,
                    binary=bench_path,
                    label=label,
                    gem5_kwargs=kwargs,
                    metadata={
                        "prefetcher": prefetcher["label"],
                        "benchmark": bench_name,
                    },
                )
            )

    output_dir = resolve_output_dir("prefetch-ghb", args.out)
    result = run_suite("prefetch-ghb", experiments, output_dir, run_nocache=False)

    if result == 0:
        print("\n" + "="*80)
        print("GHB Performance Comparison (GHB vs Baseline Stride)")
        print("="*80)

        # Parse results and display comparison table
        try:
            csv_file = output_dir / "all_results.csv"
            if csv_file.exists():
                with open(csv_file, 'r') as f:
                    reader = csv.DictReader(f)
                    rows = list(reader)

                # Group by benchmark
                benchmarks_data = {}
                for row in rows:
                    bench = row.get('benchmark', '')
                    pref = row.get('prefetcher', '')

                    if bench not in benchmarks_data:
                        benchmarks_data[bench] = {}

                    if 'BaselineStride' in pref:
                        benchmarks_data[bench]['baseline'] = row
                    elif 'GHB_LiteStudent' in pref:
                        benchmarks_data[bench]['ghb'] = row

                # Display table header
                print(f"{'Benchmark':<14} | {'Base_IPC':>9} | {'GHB_IPC':>8} | {'ΔIPC':>8} | {'ΔL1D_MPKI':>11} | {'ΔL2_MPKI':>10}")
                print("-" * 80)

                total_ipc_delta = 0
                valid_count = 0

                # Display each benchmark
                for bench in FIXED_BENCHMARKS:
                    if bench not in benchmarks_data:
                        continue
                    data = benchmarks_data[bench]
                    if 'baseline' not in data or 'ghb' not in data:
                        continue

                    baseline = data['baseline']
                    ghb = data['ghb']

                    # Extract metrics
                    base_ipc = float(baseline.get('caches_ipc', 0))
                    ghb_ipc = float(ghb.get('caches_ipc', 0))
                    base_l1d = float(baseline.get('caches_l1d_mpki', 0))
                    ghb_l1d = float(ghb.get('caches_l1d_mpki', 0))
                    base_l2 = float(baseline.get('caches_l2_mpki', 0))
                    ghb_l2 = float(ghb.get('caches_l2_mpki', 0))

                    # Calculate deltas (percentage changes)
                    delta_ipc = ((ghb_ipc - base_ipc) / base_ipc * 100) if base_ipc > 0 else 0
                    delta_l1d = ((ghb_l1d - base_l1d) / base_l1d * 100) if base_l1d > 0 else 0
                    delta_l2 = ((ghb_l2 - base_l2) / base_l2 * 100) if base_l2 > 0 else 0

                    print(f"{bench:<14} | {base_ipc:>9.3f} | {ghb_ipc:>8.3f} | {delta_ipc:>+7.2f}% | {delta_l1d:>+10.2f}% | {delta_l2:>+9.2f}%")

                    total_ipc_delta += delta_ipc
                    valid_count += 1

                print("="*80)
                if valid_count > 0:
                    avg_ipc_improvement = total_ipc_delta / valid_count
                    print(f"Average IPC Improvement: {avg_ipc_improvement:+.2f}%")
                    print("="*80)
                    print()

                    if avg_ipc_improvement > 15:
                        print(f"✓ GHB shows strong performance improvement ({avg_ipc_improvement:+.2f}%)")
                    elif avg_ipc_improvement > 5:
                        print(f"✓ GHB shows moderate performance improvement ({avg_ipc_improvement:+.2f}%)")
                    elif avg_ipc_improvement > 0:
                        print(f"○ GHB shows minor performance improvement ({avg_ipc_improvement:+.2f}%)")
                    else:
                        print(f"✗ GHB shows performance degradation ({avg_ipc_improvement:+.2f}%) - needs improvement")
                    print()
        except Exception as e:
            print(f"Warning: Could not generate comparison table: {e}")

    return result


def cmd_build(args: argparse.Namespace) -> int:
    """Build gem5 binaries (gem5.fast or ghb_history.test.opt)."""
    gem5_root = check_gem5_home(require_binary=False)
    jobs = args.jobs or os.cpu_count() or 1
    target = args.target

    # Define build targets
    BUILD_TARGETS = {
        "gem5": "build/RISCV/gem5.fast",
        "ghb-test": "build/RISCV/mem/cache/prefetch/ghb_history.test.opt",
    }

    if target == "all":
        targets_to_build = list(BUILD_TARGETS.values())
    elif target in BUILD_TARGETS:
        targets_to_build = [BUILD_TARGETS[target]]
    else:
        print(f"ERROR: Unknown build target '{target}'", file=sys.stderr)
        print(f"Available targets: {', '.join(BUILD_TARGETS.keys())}, all", file=sys.stderr)
        return 1

    for build_target in targets_to_build:
        build_cmd = ["scons", f"-j{jobs}", build_target]
        print(f"[build] Building {build_target} via: {' '.join(build_cmd)}")
        build_proc = subprocess.run(build_cmd, cwd=gem5_root)
        if build_proc.returncode != 0:
            print(f"[build] ERROR: Failed to build {build_target}", file=sys.stderr)
            return build_proc.returncode

        binary = gem5_root / build_target
        if not binary.exists():
            print(f"[build] ERROR: Binary not found at {binary}", file=sys.stderr)
            return 1
        print(f"[build] Successfully built {binary}")

    return 0


# ============================================================================
# Legacy commands (test, metrics, list)
# ============================================================================


def cmd_test(args: argparse.Namespace) -> int:
    """Run a single benchmark test (nocache vs caches)."""
    check_gem5_home()

    # Resolve program path
    if args.benchmark:
        # Use benchmark name from registry
        if args.benchmark not in BENCHMARKS:
            print(f"ERROR: Unknown benchmark '{args.benchmark}'", file=sys.stderr)
            print(f"Available benchmarks: {', '.join(BENCHMARKS.keys())}", file=sys.stderr)
            return 1
        prog = BENCHMARKS[args.benchmark]
    elif args.prog:
        # Use direct path
        prog = args.prog
    else:
        # Default fallback
        prog = str(SCRIPT_DIR / "hello.riscv")

    # Setup other defaults
    cpu = args.cpu or "TimingSimpleCPU"
    mem = args.mem or "1GB"

    # Output directory
    if args.out:
        output_dir = Path(args.out)
        output_dir.mkdir(parents=True, exist_ok=True)
    else:
        prog_name = Path(prog).stem
        output_dir = ensure_subdir("single_test", f"m5out_{prog_name}")

    # Parse flags
    enable_drrip = args.enable_drrip
    enable_ghb = args.enable_ghb_prefetch
    enable_tage = args.enable_tage_lite
    bp_type = args.bp_type

    # Run nocache and caches in parallel
    import threading

    print("\n==> Running nocache and caches in parallel")

    results = {}

    def run_case(case_name):
        try:
            ret = run_gem5(
                prog=prog,
                output_dir=output_dir,
                case=case_name,
                cpu=cpu,
                mem=mem,
                enable_drrip=enable_drrip,
                enable_ghb=enable_ghb,
                enable_tage=enable_tage,
                bp_type=bp_type,
                prog_args=args.prog_args,
                gem5_home=GEM5_HOME,
                gshare_history_bits=args.gshare_history_bits,
                gshare_index_bits=args.gshare_index_bits,
                gshare_ctr_bits=args.gshare_ctr_bits,
            )
            results[case_name] = ret
        except Exception as e:
            print(f"ERROR in {case_name}: {e}", file=sys.stderr)
            results[case_name] = 1

    # Start both threads
    nocache_thread = threading.Thread(target=run_case, args=("nocache",))
    caches_thread = threading.Thread(target=run_case, args=("caches",))

    nocache_thread.start()
    caches_thread.start()

    # Wait for both to complete
    nocache_thread.join()
    caches_thread.join()

    # Check results
    if results.get("nocache", 1) != 0:
        print("ERROR: nocache simulation failed", file=sys.stderr)
        return results["nocache"]
    if results.get("caches", 1) != 0:
        print("ERROR: caches simulation failed", file=sys.stderr)
        return results["caches"]

    print(f"\nDone. Outputs in: {output_dir}")
    print(f"  nocache: {output_dir}/nocache")
    print(f"  caches:  {output_dir}/caches")

    return 0


def cmd_metrics(args: argparse.Namespace) -> int:
    """Compare test results using metrics extraction."""
    targets = args.targets

    # Validate targets
    for target in targets:
        path_str = target.split("=")[-1] if "=" in target else target
        path = Path(path_str)
        stats_path = path / "stats.txt" if path.is_dir() else path

        if not stats_path.exists():
            print(f"ERROR: stats.txt not found at {path}", file=sys.stderr)
            return 1

    # Build args for metrics
    metrics_args = targets[:]
    if args.format:
        metrics_args.extend(["--format", args.format])

    return metrics_main(metrics_args)


def cmd_list(args: argparse.Namespace) -> int:
    """List available benchmarks."""
    print("Available Benchmarks")
    print("=" * 80)
    print()

    for name, rel_path in BENCHMARKS.items():
        status = "✓" if (SCRIPT_DIR / rel_path).exists() else "✗"
        print(f"  {status} {name:<20} - {rel_path}")

    print()
    print("Usage:")
    print("  ./main.py suite <command> --benchmarks <name>")
    print()

    return 0


def cmd_submit(args: argparse.Namespace) -> int:
    """Package student submission with gem5 source and experiment outputs."""
    student_id = args.student_id
    output_file = args.output if args.output else f"{student_id}_submission.tar.gz"

    print("="*80)
    print(f"Creating submission package for student: {student_id}")
    print("="*80)
    print()

    # Get GEM5_HOME (parent directory containing both gem5 and formace-lab)
    gem5_root = check_gem5_home(require_binary=False)

    # formace-lab should be sibling to gem5 root, or we're already in it
    if (gem5_root / "formace-lab").exists():
        # We're in the parent (final/) directory
        parent_dir = gem5_root
        formace_lab_dir = parent_dir / "formace-lab"
    elif SCRIPT_DIR.name == "formace-lab":
        # We're already in formace-lab
        formace_lab_dir = SCRIPT_DIR
        parent_dir = formace_lab_dir.parent
    else:
        print(f"ERROR: Cannot find formace-lab directory", file=sys.stderr)
        print(f"Current dir: {SCRIPT_DIR}", file=sys.stderr)
        print(f"GEM5_HOME: {gem5_root}", file=sys.stderr)
        return 1

    # Check if output/<student_id> exists
    student_output_dir = formace_lab_dir / "output" / student_id
    if not student_output_dir.exists():
        print(f"ERROR: Student output directory not found: {student_output_dir}", file=sys.stderr)
        print(f"Please run your experiments first with --out output/{student_id}/...", file=sys.stderr)
        return 1

    print(f"Found student outputs: {student_output_dir}")
    print()

    # Create temporary directory for tarball creation
    import tempfile
    import shutil

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        # Create tarball
        print("Creating tarball...")
        print(f"  - Including formace-lab/")
        print(f"  - Including output/{student_id}/")
        print(f"  - Including gem5 source (src/, configs/, etc.)")
        print()

        # Build exclude list - exclude other output directories
        # First, get list of all output directories
        output_dirs = []
        if (formace_lab_dir / "output").exists():
            for item in (formace_lab_dir / "output").iterdir():
                if item.is_dir() and item.name != student_id:
                    output_dirs.append(f"--exclude=formace-lab/output/{item.name}")

        excludes = [
            "--exclude=formace-lab/venv",
            "--exclude=formace-lab/.venv",
            "--exclude=formace-lab/scripts",
            "--exclude=formace-lab/golden",
            "--exclude=formace-lab/logs",
            "--exclude=formace-lab/.claude",
            "--exclude=formace-lab/__pycache__",
            "--exclude=formace-lab/.pytest_cache",
            "--exclude=formace-lab/**/*.pyc",
            "--exclude=formace-lab/**/*.pyo",
            "--exclude=formace-lab/demo",
            "--exclude=formace-lab/references",
            "--exclude=formace-lab/student_scores",
            *output_dirs,  # Exclude all OTHER student output directories
            "--exclude=build",
            "--exclude=m5out",
            "--exclude=.git",
            "--exclude=.github",
            "--exclude=.pytest_cache",
            "--exclude=__pycache__",
            "--exclude=*.pyc",
            "--exclude=*.pyo",
            "--exclude=*.o",
            "--exclude=*.d",
            "--exclude=.sconsign.dblite",
        ]

        # Change to parent directory
        os.chdir(parent_dir)

        # Create tarball command
        cmd = [
            "tar", "-czf", str(Path(output_file).absolute()),
            *excludes,
            "formace-lab/",
            "build_opts/",
            "build_tools/",
            "configs/",
            "ext/",
            "include/",
            "src/",
            "system/",
            "util/",
            "site_scons/",
            "SConstruct",
            "COPYING",
            "LICENSE",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"ERROR: Failed to create tarball", file=sys.stderr)
            print(result.stderr, file=sys.stderr)
            return 1

    # Get tarball size
    tarball_path = Path(output_file).absolute()
    size_mb = tarball_path.stat().st_size / (1024 * 1024)

    print("="*80)
    print("Submission package created successfully!")
    print("="*80)
    print()
    print(f"Output file: {tarball_path}")
    print(f"Size: {size_mb:.1f} MB")
    print()
    print("Next steps:")
    print("  1. Verify the package contains your implementations")
    print("  2. Submit the tarball according to course instructions")
    print()

    return 0


# ============================================================================
# CLI wiring
# ============================================================================


def main() -> int:
    # Check venv (optional warning)
    check_venv()

    parser = argparse.ArgumentParser(
        description="formace-lab - Unified testing framework for gem5 microarchitecture optimizations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./main.py suite cache-size --benchmarks smoky --l1d-sizes 8kB 32kB 64kB --l2-size 256kB
  ./main.py suite cache-policy --benchmarks smoky --cache-policy LRU FIFO TreePLRU
  ./main.py suite branch --workloads microbench --predictors LocalBP BiModeBP
  ./main.py suite prefetch-upstream --benchmarks smoky --prefetchers StridePrefetcher AMPMPPrefetcher
  ./main.py suite prefetch-ghb --benchmarks smoky --prefetchers BaselineStride GHB_LiteStudent
  ./main.py metrics logs_case1/run_*/**/caches --format csv
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ===== test command =====
    parser_test = subparsers.add_parser(
        "test",
        help="Run a single benchmark test",
        description="Run a single benchmark test (nocache vs caches)",
    )
    parser_test.add_argument("--prog", help="Program path to test (or use --benchmark)")
    parser_test.add_argument("--benchmark", help="Benchmark name from registry (e.g., branch_corr, mm, smoky)")
    parser_test.add_argument("--cpu", help="CPU type (default: TimingSimpleCPU)")
    parser_test.add_argument("--mem", help="Memory size (default: 1GB)")
    parser_test.add_argument("--out", help="Output directory")
    parser_test.add_argument("--prog-args", help="Program arguments", default="")
    parser_test.add_argument("--enable-drrip", action="store_true", help="Enable DRRIP")
    parser_test.add_argument("--enable-ghb-prefetch", action="store_true", help="Enable GHB")
    parser_test.add_argument("--enable-tage-lite", action="store_true", help="Enable TAGE")
    parser_test.add_argument("--bp-type", help="Override branch predictor type (e.g., TAGE)")
    parser_test.add_argument("--gshare-history-bits", type=int, help="History bits for GShareBP")
    parser_test.add_argument("--gshare-index-bits", type=int, help="Index bits for GShareBP")
    parser_test.add_argument("--gshare-ctr-bits", type=int, help="Counter bits for GShareBP")
    parser_test.set_defaults(func=cmd_test)

    # ===== metrics command =====
    parser_metrics = subparsers.add_parser(
        "metrics",
        help="Compare test results",
        description="Extract and compare PMU metrics from stats.txt files",
    )
    parser_metrics.add_argument(
        "targets",
        nargs="+",
        help="Output directories or stats.txt files. Optionally prefix with label=path",
    )
    parser_metrics.add_argument(
        "--format",
        choices=("table", "csv"),
        default="table",
        help="Output format (default: table)",
    )
    parser_metrics.set_defaults(func=cmd_metrics)

    # ===== list command =====
    parser_list = subparsers.add_parser(
        "list",
        help="List available benchmarks",
        description="Show all available benchmarks",
    )
    parser_list.set_defaults(func=cmd_list)

    # ===== example command =====
    parser_example = subparsers.add_parser(
        "example",
        help="Run Case 1.1 (L1 cache size sweep) with PMU summary",
        description="Case 1.1 (Teaching Example): L1 cache size sweep with PMU metrics displayed.",
    )
    parser_example.add_argument(
        "--benchmarks",
        nargs="+",
        default=["mm"],
        help="Benchmarks to run (default: mm)",
    )
    parser_example.add_argument("--l1i-size", default="32kB", help="L1 I-cache size (default: 32kB)")
    parser_example.add_argument("--l1d-size", default="32kB", help="Default L1 D-cache size (default: 32kB)")
    parser_example.add_argument("--l2-size", default="256kB", help="Default L2 size (default: 256kB)")
    parser_example.add_argument("--l1d-sizes", nargs="+", help="Sweep list for L1D sizes")
    parser_example.add_argument("--l2-sizes", nargs="+", help="Sweep list for L2 sizes")
    parser_example.add_argument("--out", help="Output directory (default: example/<run_id>)")
    parser_example.set_defaults(func=example_cache_size)

    # ===== suite command =====
    parser_suite = subparsers.add_parser(
        "suite",
        help="Run final project cases",
        description="Launch cache, branch, and prefetcher experiments via subcommands.",
    )
    suite_subparsers = parser_suite.add_subparsers(dest="suite_case", required=True)

    def add_cache_common_args(p, include_sizes: bool = True):
        p.add_argument(
            "--benchmarks",
            nargs="+",
            default=["smoky"],
            help="Benchmarks to run (default: smoky)",
        )
        p.add_argument("--l1i-size", default="32kB", help="L1 I-cache size (default: 32kB)")
        p.add_argument("--l1d-size", default="32kB", help="Default L1 D-cache size (default: 32kB)")
        p.add_argument("--l2-size", default="256kB", help="Default L2 size (default: 256kB)")
        p.add_argument("--out", help="Output directory (default: logs_case*/<run_id>)")
        if include_sizes:
            p.add_argument("--l1d-sizes", nargs="+", help="Sweep list for L1D sizes")
            p.add_argument("--l2-sizes", nargs="+", help="Sweep list for L2 sizes")

    cache_size_parser = suite_subparsers.add_parser(
        "cache-size",
        help="Case 1.1 cache size sweep",
        description="Run L1/L2 cache size sweeps using O3CPU.",
    )
    add_cache_common_args(cache_size_parser, include_sizes=True)
    cache_size_parser.set_defaults(func=suite_cache_size)

    cache_policy_parser = suite_subparsers.add_parser(
        "cache-policy",
        help="Case 1.2 replacement policy study",
        description="Compare LRU/FIFO/TreePLRU policies.",
    )
    add_cache_common_args(cache_policy_parser, include_sizes=False)
    cache_policy_parser.add_argument(
        "--cache-policy",
        nargs="+",
        default=["LRU", "FIFO", "TreePLRU"],
        help="Replacement policies to evaluate",
    )
    cache_policy_parser.set_defaults(func=suite_cache_policy)

    branch_parser = suite_subparsers.add_parser(
        "branch",
        help="Case 2 branch predictor study",
        description="Run workloads across LocalBP/BiModeBP/etc.",
    )
    branch_parser.add_argument(
        "--benchmarks",
        nargs="+",
        default=["smoky"],
        help="Benchmarks to run (microbench expands to towers/pointer_chase/binary_search)",
    )
    branch_parser.add_argument(
        "--predictors",
        nargs="+",
        default=["LocalBP", "BiModeBP"],
        help="Branch predictors to compare",
    )
    branch_parser.add_argument("--l1i-size", default="32kB", help="L1 I-cache size (default: 32kB)")
    branch_parser.add_argument("--l1d-size", default="32kB", help="L1 D-cache size (default: 32kB)")
    branch_parser.add_argument("--l2-size", default="256kB", help="L2 size (default: 256kB)")
    branch_parser.add_argument("--out", help="Output directory (default: logs_case2/<run_id>)")
    branch_parser.set_defaults(func=suite_branch)

    prefetch_up_parser = suite_subparsers.add_parser(
        "prefetch-upstream",
        help="Case 3.1 upstream prefetcher tuning",
        description="Sweep Stride degree and compare AMPMP/BOP/Stride prefetchers.",
    )
    add_cache_common_args(prefetch_up_parser, include_sizes=False)
    prefetch_up_parser.add_argument(
        "--prefetchers",
        nargs="+",
        default=["StridePrefetcher", "AMPMPPrefetcher", "BOPPrefetcher"],
        help="Prefetchers to evaluate",
    )
    prefetch_up_parser.add_argument(
        "--stride-degree",
        nargs="+",
        type=int,
        default=[1, 2, 4],
        help="Stride degrees to test (StridePrefetcher only)",
    )
    prefetch_up_parser.set_defaults(func=suite_prefetch_upstream)

    prefetch_ghb_parser = suite_subparsers.add_parser(
        "prefetch-ghb",
        help="Case 3.2 GHB-lite bring-up",
        description="Compare BaselineStride vs GHB_LiteStudent implementations.",
    )
    add_cache_common_args(prefetch_ghb_parser, include_sizes=False)
    prefetch_ghb_parser.add_argument(
        "--prefetchers",
        nargs="+",
        default=["BaselineStride", "GHB_LiteStudent"],
        help="Prefetchers to evaluate",
    )
    prefetch_ghb_parser.add_argument(
        "--stride-degree",
        nargs="+",
        type=int,
        default=[1],
        help="Stride degree for BaselineStride",
    )
    prefetch_ghb_parser.set_defaults(func=suite_prefetch_ghb)

    parser_build = subparsers.add_parser(
        "build",
        help="Build gem5 binaries (requires GEM5_HOME).",
    )
    parser_build.add_argument(
        "--target",
        type=str,
        choices=["gem5", "ghb-test", "all"],
        default="gem5",
        help="Build target: gem5 (gem5.fast), ghb-test (ghb_history.test.opt), or all (default: gem5)",
    )
    parser_build.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=os.cpu_count() or 1,
        help="Parallel jobs for scons (default: host CPU count)",
    )
    parser_build.set_defaults(func=cmd_build)

    parser_submit = subparsers.add_parser(
        "submit",
        help="Package student submission (gem5 source + output/<student_id>).",
    )
    parser_submit.add_argument(
        "student_id",
        type=str,
        help="Student ID (e.g., B12345678)",
    )
    parser_submit.add_argument(
        "-o",
        "--output",
        type=str,
        help="Output tarball path (default: <student_id>_submission.tar.gz)",
    )
    parser_submit.set_defaults(func=cmd_submit)

    # Parse and execute
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.command != "suite":
        return args.func(args)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
