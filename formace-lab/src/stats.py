"""gem5 statistics extraction utilities."""

import re
from pathlib import Path
from typing import Dict


def extract_stat(stats_file: Path, pattern: str) -> str:
    """Extract a single stat from stats.txt.

    Args:
        stats_file: Path to stats.txt
        pattern: Regex pattern to match

    Returns:
        Stat value or "N/A" if not found
    """
    try:
        with stats_file.open() as f:
            for line in f:
                if re.match(pattern, line):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
    except Exception:
        pass
    return "N/A"


def extract_metrics_from_stats(stats_file: Path) -> Dict[str, str]:
    """Extract key metrics from stats.txt.

    Args:
        stats_file: Path to stats.txt

    Returns:
        Dictionary of metrics
    """
    if not stats_file.exists():
        return {}

    metrics = {
        "ipc": extract_stat(stats_file, r"^system\.cpu\.ipc\s"),
        "sim_seconds": extract_stat(stats_file, r"^simSeconds\s"),
        "num_cycles": extract_stat(stats_file, r"^system\.cpu\.numCycles\s"),
        "num_insts": extract_stat(stats_file, r"^system\.cpu\.committedInsts\s"),
        "l2_misses": extract_stat(stats_file, r"^system\.l2\.overall_misses::total\s"),
        "l2_accesses": extract_stat(stats_file, r"^system\.l2\.overall_accesses::total\s"),
        "branch_mispreds": extract_stat(stats_file, r"^system\.cpu\.branchPred\.condIncorrect\s"),
    }

    # Calculate L2 MPKI
    if metrics["num_insts"] != "N/A" and metrics["l2_misses"] != "N/A":
        try:
            insts = float(metrics["num_insts"])
            misses = float(metrics["l2_misses"])
            if insts > 0:
                metrics["l2_mpki"] = f"{1000.0 * misses / insts:.2f}"
            else:
                metrics["l2_mpki"] = "N/A"
        except:
            metrics["l2_mpki"] = "N/A"
    else:
        metrics["l2_mpki"] = "N/A"

    return metrics
