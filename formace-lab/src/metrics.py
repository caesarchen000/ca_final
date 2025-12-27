#!/usr/bin/env python3
"""
Summarize common PMU-style metrics from gem5 stats.txt files.

Usage examples:
  ./extract_pmu_metrics.py output/20240212_101500/cases/mm/nocache output/20240212_101500/cases/mm/caches
  ./extract_pmu_metrics.py baseline=output/20240212_101500/batch/all_benchmarks stats2.txt --format csv

Each target may be a gem5 output directory or an explicit stats.txt file.
For convenience, arguments can include an optional "label=path" prefix to
override the display name in the output table.
"""

from __future__ import annotations

import argparse
import csv
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple


StatDict = Dict[str, float]
Extractor = Callable[[StatDict], Optional[float]]


@dataclass(frozen=True)
class Metric:
    """Definition of a derived metric to report."""

    key: str
    description: str
    extractor: Extractor


def _value_from_stat(stat_name: str) -> Extractor:
    return lambda stats: stats.get(stat_name)


def _mpki(stat_name: str) -> Extractor:
    def extractor(stats: StatDict) -> Optional[float]:
        insts = stats.get("simInsts")
        misses = stats.get(stat_name)
        if insts in (None, 0) or misses is None:
            return None
        return 1000.0 * misses / insts

    return extractor


METRICS: Tuple[Metric, ...] = (
    Metric("sim_insts", "Simulated instructions", _value_from_stat("simInsts")),
    Metric("sim_secs", "Simulated seconds", _value_from_stat("simSeconds")),
    Metric("ipc", "Core IPC", _value_from_stat("system.cpu.ipc")),
    Metric("cpi", "Core CPI", _value_from_stat("system.cpu.cpi")),
    Metric("branch_rate", "Fetched branches per cycle", _value_from_stat("system.cpu.fetchStats0.branchRate")),
    Metric("branch_mpki", "Cond. branch MPKI", _mpki("system.cpu.branchPred.condIncorrect")),
    Metric("l1i_miss", "L1I misses", _value_from_stat("system.cpu.icache.overallMisses::total")),
    Metric("l1i_mpki", "L1I MPKI", _mpki("system.cpu.icache.overallMisses::total")),
    Metric("l1d_miss", "L1D misses", _value_from_stat("system.cpu.dcache.overallMisses::total")),
    Metric("l1d_mpki", "L1D MPKI", _mpki("system.cpu.dcache.overallMisses::total")),
    Metric("l2_miss", "L2 misses", _value_from_stat("system.l2.overallMisses::total")),
    Metric("l2_mpki", "L2 MPKI", _mpki("system.l2.overallMisses::total")),
    Metric("prefetch_issued", "Prefetches issued", _value_from_stat("system.l2.prefetcher.numPrefetches")),
    Metric("prefetch_useful", "Useful prefetches", _value_from_stat("system.l2.prefetcher.usefulPrefetches")),
    Metric("prefetch_accuracy", "Prefetch accuracy", _value_from_stat("system.l2.prefetcher.accuracy")),
    Metric("prefetch_coverage", "Prefetch coverage", _value_from_stat("system.l2.prefetcher.coverage")),
    Metric("dram_reads", "DRAM read responses", _value_from_stat("system.mem_ctrls.dram.numReads::total")),
    Metric("dram_writes", "DRAM write responses", _value_from_stat("system.mem_ctrls.dram.numWrites::total")),
    Metric("dram_bw", "Total DRAM bandwidth", _value_from_stat("system.mem_ctrls.dram.bwTotal")),
)


def parse_stats(path: Path) -> StatDict:
    stats: StatDict = {}
    with path.open() as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-") or line.startswith("="):
                continue
            if line.startswith("----------"):
                # Skip the explicit section markers.
                continue
            if "#" in line:
                line = line.split("#", 1)[0].rstrip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            name, raw_value = parts[0], parts[1]
            try:
                value = float(raw_value)
            except ValueError:
                continue
            stats[name] = value
    return stats


def format_value(value: Optional[float]) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        if math.isnan(value):
            return "nan"
        if value.is_integer():
            return str(int(value))
        magnitude = abs(value)
        if magnitude >= 1000:
            return f"{value:.2e}"
        if magnitude >= 100:
            return f"{value:.2f}"
        if magnitude >= 1:
            return f"{value:.3f}"
        return f"{value:.4f}"
    return str(value)


def render_table(rows: List[Dict[str, Optional[float]]], headers: List[str]) -> str:
    formatted_rows: List[List[str]] = []
    widths = {h: len(h) for h in headers}
    for row in rows:
        formatted_row = []
        for h in headers:
            text = format_value(row.get(h))
            formatted_row.append(text)
            widths[h] = max(widths[h], len(text))
        formatted_rows.append(formatted_row)

    lines = []
    header_line = "  ".join(h.ljust(widths[h]) for h in headers)
    sep_line = "  ".join("-" * widths[h] for h in headers)
    lines.append(header_line)
    lines.append(sep_line)
    for formatted_row in formatted_rows:
        line = "  ".join(text.ljust(widths[headers[i]]) for i, text in enumerate(formatted_row))
        lines.append(line)
    return "\n".join(lines)


def resolve_target(target: str) -> Tuple[str, Path]:
    label: Optional[str] = None
    path_str = target
    if "=" in target:
        maybe_label, maybe_path = target.split("=", 1)
        label = maybe_label.strip()
        path_str = maybe_path.strip()
    path = Path(path_str)
    stats_path = path / "stats.txt" if path.is_dir() else path
    if not stats_path.is_file():
        raise FileNotFoundError(f"stats.txt not found at {path}")
    if label is None:
        parts = stats_path.parent.parts
        label = "/".join(parts[-2:]) if len(parts) >= 2 else stats_path.parent.name or stats_path.name
    return label, stats_path


def collect_metrics(stats: StatDict) -> Dict[str, Optional[float]]:
    return {metric.key: metric.extractor(stats) for metric in METRICS}


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Extract frequently used PMU-style metrics from gem5 stats.txt outputs.")
    parser.add_argument("targets", nargs="+", help="Gem5 output directories or stats.txt files. Optionally prefix with label=path.")
    parser.add_argument(
        "--format",
        choices=("table", "csv"),
        default="table",
        help="Output format (default: table).",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    rows: List[Dict[str, Optional[float]]] = []
    for target in args.targets:
        label, stats_path = resolve_target(target)
        stats = parse_stats(stats_path)
        data = collect_metrics(stats)
        data["run"] = label
        rows.append(data)

    headers = ["run"] + [metric.key for metric in METRICS]

    if args.format == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            serialized = {}
            for h in headers:
                value = row.get(h)
                if value is None:
                    serialized[h] = ""
                elif isinstance(value, float) and math.isnan(value):
                    serialized[h] = "nan"
                else:
                    serialized[h] = value
            writer.writerow(serialized)
    else:
        print(render_table(rows, headers))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
