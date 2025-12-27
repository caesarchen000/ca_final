"""Helpers for Case 1 verification (cache hierarchy metrics)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Sequence

from metrics import parse_stats


StatDict = Dict[str, float]

L1D_HIT_KEYS: Sequence[str] = (
    "system.cpu.dcache.overallHits::total",
    "system.cpu.dcache.overall_hits::total",
)
L1D_MISS_KEYS: Sequence[str] = (
    "system.cpu.dcache.overallMisses::total",
    "system.cpu.dcache.overall_misses::total",
)
L2_HIT_KEYS: Sequence[str] = (
    "system.l2.overallHits::total",
    "system.l2.overall_hits::total",
)
L2_MISS_KEYS: Sequence[str] = (
    "system.l2.overallMisses::total",
    "system.l2.overall_misses::total",
)
IPC_KEYS: Sequence[str] = (
    "system.cpu.ipc",
    "system.cpu.commitStats0.ipc",
)


def _first_available(stats: StatDict, keys: Sequence[str]) -> Optional[float]:
    for key in keys:
        value = stats.get(key)
        if value is not None:
            return value
    return None


def _miss_rate(stats: StatDict, hit_keys: Sequence[str], miss_keys: Sequence[str]) -> Optional[float]:
    hits = _first_available(stats, hit_keys)
    misses = _first_available(stats, miss_keys)
    if hits is None or misses is None:
        return None
    total = hits + misses
    if total == 0:
        return None
    return misses / total


def _resolve_stats_path(path: Path) -> Path:
    if path.is_dir():
        path = path / "stats.txt"
    if not path.exists():
        raise FileNotFoundError(f"stats.txt not found: {path}")
    return path


@dataclass(frozen=True)
class Case1Report:
    """Derived metrics for Case 1 validation."""

    l1d_miss_rate_nocache: Optional[float]
    l1d_miss_rate_caches: Optional[float]
    l2_miss_rate_nocache: Optional[float]
    l2_miss_rate_caches: Optional[float]
    ipc_nocache: Optional[float]
    ipc_caches: Optional[float]
    ipc_speedup: Optional[float]


def load_stats(path: Path) -> StatDict:
    """Load stats.txt from a directory or explicit file."""
    stats_path = _resolve_stats_path(path)
    return parse_stats(stats_path)


def compute_case1_report(nocache_stats: StatDict, caches_stats: StatDict) -> Case1Report:
    """Compute miss rates and IPC speedup for Case 1."""
    l1d_nocache = _miss_rate(nocache_stats, L1D_HIT_KEYS, L1D_MISS_KEYS)
    l1d_caches = _miss_rate(caches_stats, L1D_HIT_KEYS, L1D_MISS_KEYS)
    l2_nocache = _miss_rate(nocache_stats, L2_HIT_KEYS, L2_MISS_KEYS)
    l2_caches = _miss_rate(caches_stats, L2_HIT_KEYS, L2_MISS_KEYS)

    ipc_nocache = _first_available(nocache_stats, IPC_KEYS)
    ipc_caches = _first_available(caches_stats, IPC_KEYS)
    ipc_speedup = None
    if ipc_nocache not in (None, 0) and ipc_caches is not None:
        ipc_speedup = ipc_caches / ipc_nocache

    return Case1Report(
        l1d_miss_rate_nocache=l1d_nocache,
        l1d_miss_rate_caches=l1d_caches,
        l2_miss_rate_nocache=l2_nocache,
        l2_miss_rate_caches=l2_caches,
        ipc_nocache=ipc_nocache,
        ipc_caches=ipc_caches,
        ipc_speedup=ipc_speedup,
    )


def format_case1_report(report: Case1Report) -> str:
    """Render the Case 1 report as human-friendly text."""

    def pct(value: Optional[float]) -> str:
        if value is None:
            return "N/A"
        return f"{value * 100:.2f}%"

    def num(value: Optional[float]) -> str:
        if value is None:
            return "N/A"
        return f"{value:.4f}"

    lines = [
        "Case 1 Cache Hierarchy Metrics",
        "--------------------------------",
        f"L1D miss rate (nocache): {pct(report.l1d_miss_rate_nocache)}",
        f"L1D miss rate (caches): {pct(report.l1d_miss_rate_caches)}",
        f"L2 miss rate (nocache): {pct(report.l2_miss_rate_nocache)}",
        f"L2 miss rate (caches): {pct(report.l2_miss_rate_caches)}",
        f"IPC (nocache): {num(report.ipc_nocache)}",
        f"IPC (caches): {num(report.ipc_caches)}",
        f"IPC speedup: {num(report.ipc_speedup)}",
    ]
    return "\n".join(lines)
