"""gem5 simulator interface."""

import subprocess
from pathlib import Path
from typing import Optional

from signature import append_signature_to_stats


def run_gem5(
    prog: str,
    output_dir: Path,
    case: str = "caches",
    cpu: str = "TimingSimpleCPU",
    mem: str = "1GB",
    enable_drrip: bool = False,
    enable_ghb: bool = False,
    enable_tage: bool = False,
    bp_type: Optional[str] = None,
    prog_args: str = "",
    gem5_home: str = "",
    l2_hwp_type: Optional[str] = None,
    l2_rp_type: Optional[str] = None,
    l1i_size: Optional[str] = None,
    l1d_size: Optional[str] = None,
    l2_size: Optional[str] = None,
    mockingjay_weights_file: Optional[str] = None,
    mockingjay_online_learning: Optional[bool] = None,
    gshare_history_bits: Optional[int] = None,
    gshare_index_bits: Optional[int] = None,
    gshare_ctr_bits: Optional[int] = None,
    stride_degree: Optional[int] = None,
) -> int:
    """Run a single gem5 simulation.

    Args:
        prog: Path to program binary
        output_dir: Output directory
        case: Simulation case ("nocache" or "caches")
        cpu: CPU type
        mem: Memory size
        enable_drrip: Enable DRRIP replacement policy
        enable_ghb: Enable GHB prefetcher
        enable_tage: Enable TAGE-LITE branch predictor
        bp_type: Override branch predictor type (takes precedence)
        prog_args: Program arguments
        gem5_home: gem5 installation path

    Returns:
        Exit code (0 for success)
    """
    # Resolve gem5 paths
    gem5_path = Path(gem5_home)
    gem5_bin = gem5_path / "build" / "RISCV" / "gem5.fast"
    se_cfg = gem5_path / "configs" / "deprecated" / "example" / "se.py"

    if not gem5_bin.exists():
        raise FileNotFoundError(f"gem5 binary not found at {gem5_bin}")
    if not se_cfg.exists():
        raise FileNotFoundError(f"se.py not found at {se_cfg}")

    # Create output directory
    case_dir = output_dir / case
    case_dir.mkdir(parents=True, exist_ok=True)

    # Build command
    cmd = [
        str(gem5_bin),
        f"--outdir={case_dir}",
        str(se_cfg),
        "-c", prog,
        f"--cpu-type={cpu}",
        f"--mem-size={mem}",
    ]

    if prog_args:
        cmd.extend(["-o", prog_args])

    # Add optimizations
    prefetcher = l2_hwp_type or ("GHBPrefetcher" if enable_ghb else None)
    replacement = l2_rp_type or ("DRRIPRP" if enable_drrip else None)
    selected_bp = bp_type if bp_type else ("TAGE_LITE" if enable_tage else None)
    cache_case = case != "nocache"

    prefetcher_enabled = False
    if selected_bp:
        cmd.extend(["--bp-type", selected_bp])
    if replacement and cache_case:
        cmd.extend(["--l2-rp-type", replacement])
    if prefetcher and cache_case:
        cmd.extend(["--l2-hwp-type", prefetcher])
        prefetcher_enabled = True
    if mockingjay_weights_file:
        cmd.append(f"--mockingjay-weights-file={mockingjay_weights_file}")
    if mockingjay_online_learning:
        cmd.append("--mockingjay-online-learning")
    if gshare_history_bits is not None:
        cmd.append(f"--gshare-history-bits={gshare_history_bits}")
    if gshare_index_bits is not None:
        cmd.append(f"--gshare-index-bits={gshare_index_bits}")
    if gshare_ctr_bits is not None:
        cmd.append(f"--gshare-ctr-bits={gshare_ctr_bits}")
    if stride_degree is not None and prefetcher_enabled:
        cmd.extend(
            [
                "--param",
                f"system.l2.prefetcher.degree={stride_degree}",
            ]
        )

    # Add cache configuration for "caches" case
    # Note: O3CPU requires caches, so force caches for O3CPU
    if cache_case or cpu == "O3CPU":
        l1i = l1i_size or "32kB"
        l1d = l1d_size or "32kB"
        l2 = l2_size or "256kB"
        cmd.extend([
            "--caches", "--l2cache",
            f"--l1i_size={l1i}",
            f"--l1d_size={l1d}",
            f"--l2_size={l2}",
        ])

    # Run simulation
    result = subprocess.run(cmd, capture_output=False)

    # Append signature to stats.txt if simulation succeeded
    if result.returncode == 0:
        stats_file = case_dir / "stats.txt"
        if stats_file.exists():
            append_signature_to_stats(stats_file)

    return result.returncode
