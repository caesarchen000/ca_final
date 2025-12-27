#!/bin/bash
# Setup benchmark repositories
#
# This script clones the required benchmark repositories and builds them.
# Run this once after cloning the formace-lab repository.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================="
echo "Setting up benchmarks for formace-lab"
echo "========================================="
echo

# Create directories
mkdir -p benchmarks/demo
mkdir -p benchmarks/hidden

# Clone repositories if they don't exist
echo "1. Cloning benchmark repositories..."
echo

if [ ! -d "benchmarks/demo/coremark/.git" ]; then
    echo "  Cloning CoreMark..."
    git clone https://github.com/eembc/coremark.git benchmarks/demo/coremark
else
    echo "  ✓ CoreMark already cloned"
fi

if [ ! -d "benchmarks/demo/dhrystone/.git" ]; then
    echo "  Cloning Dhrystone..."
    git clone https://github.com/RISCV-Tools/dhrystone.git benchmarks/demo/dhrystone
else
    echo "  ✓ Dhrystone already cloned"
fi

if [ ! -d "benchmarks/demo/riscv-benchmarks/.git" ]; then
    echo "  Cloning RISC-V Benchmarks..."
    git clone https://github.com/ucb-bar/riscv-benchmarks.git benchmarks/demo/riscv-benchmarks
else
    echo "  ✓ RISC-V Benchmarks already cloned"
fi

if [ ! -d "benchmarks/hidden/embench-iot/.git" ]; then
    echo "  Cloning Embench-IoT..."
    git clone https://github.com/embench/embench-iot.git benchmarks/hidden/embench-iot
else
    echo "  ✓ Embench-IoT already cloned"
fi

echo
echo "========================================="
echo "✓ Benchmark repositories set up successfully"
echo "========================================="
echo
echo "Next steps:"
echo "  1. Build the benchmarks (see each repo's README)"
echo "  2. Run tests: ./main.py batch --quick"
echo
