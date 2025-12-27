#!/bin/bash
# Setup environment for building and running gem5 without sudo
# Source this file before running any gem5 commands:
#   source setup_env.sh

# Use system GCC instead of conda GCC (gem5 doesn't recognize conda's compiler name)
export CC=/usr/bin/gcc
export CXX=/usr/bin/g++

# Add conda libraries and headers to paths so system GCC can find them
export LD_LIBRARY_PATH=/home/caesar/miniforge3/lib:$LD_LIBRARY_PATH
export LIBRARY_PATH=/home/caesar/miniforge3/lib:$LIBRARY_PATH
export CPATH=/home/caesar/miniforge3/include:$CPATH

# Set GEM5_HOME (required by formace-lab scripts)
# IMPORTANT: This must be /home/caesar/Desktop/ca-final (NOT /home/caesar/Desktop/ca-final/gem5)
export GEM5_HOME=/home/caesar/Desktop/ca-final

# Verify the correct gem5.fast exists
if [ ! -f "$GEM5_HOME/build/RISCV/gem5.fast" ]; then
    echo "WARNING: gem5.fast not found at $GEM5_HOME/build/RISCV/gem5.fast" >&2
    echo "Make sure GEM5_HOME is set to the gem5 source directory (not a subdirectory)" >&2
fi

echo "✓ Environment configured for gem5!"
echo "  CC=$CC"
echo "  CXX=$CXX"
echo "  GEM5_HOME=$GEM5_HOME"
echo ""
echo "Now you can run:"
echo "  venv/bin/python main.py build --target gem5 --jobs \$(nproc)"
echo "  venv/bin/python main.py suite cache-size --benchmarks mm --l1d-size 32kB --l2-sizes 128kB 256kB 512kB --out output/<student_id>/case1/1-2"


