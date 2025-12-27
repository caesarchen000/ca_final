#!/usr/bin/env bash
set -euo pipefail

# Expect script to be run from formace-lab root
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
FORMACE_DIR="$ROOT_DIR"
BENCH_DIR="$SCRIPT_DIR"

GEM5_ROOT="${GEM5_ROOT:-$ROOT_DIR/..}"
RUN_SCRIPT="${RUN_SCRIPT:-$FORMACE_DIR/run_gem5.sh}"
LOG_ROOT="${LOG_ROOT:-$FORMACE_DIR/logs_simple}" 
mkdir -p "$LOG_ROOT"

if [[ ! -x "$RUN_SCRIPT" ]]; then
  echo "RUN_SCRIPT not executable: $RUN_SCRIPT" >&2
  exit 1
fi

BENCHES=(vvadd pointer_chase mm stream towers)

declare -a CONFIG_OPTS
declare -a CONFIG_SUFFIX
CONFIG_SUFFIX=(baseline drrip ghb "tage-lite")
CONFIG_OPTS=("" "--enable-drrip" "--enable-ghb-prefetch" "--enable-tage-lite")

run_case() {
  local bench="$1" bin="$2" suffix="$3" extra="$4"
  local outdir="$LOG_ROOT/${bench}_${suffix}_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$outdir"
  echo "[run_simple] $bench $suffix -> $outdir"
  LOG_DIR="$LOG_ROOT" GEM5_HOME="$GEM5_ROOT" "$RUN_SCRIPT" \
    --prog "$bin" --use-caches --outdir "$outdir" $extra
}

for bench in "${BENCHES[@]}"; do
  bin="$BENCH_DIR/${bench}.riscv"
  [[ -f "$bin" ]] || { echo "Missing $bin" >&2; exit 1; }
  for idx in "${!CONFIG_SUFFIX[@]}"; do
    run_case "$bench" "$bin" "${CONFIG_SUFFIX[$idx]}" "${CONFIG_OPTS[$idx]}"
  done
  echo "==> Completed $bench"
  sleep 1
 done
