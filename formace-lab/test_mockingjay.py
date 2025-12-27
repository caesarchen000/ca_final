#!/usr/bin/env python3
"""
Quick test script for Mockingjay replacement policy.
Runs a simple benchmark with Mockingjay and verifies it works.
"""

import sys
import os

# Add gem5 to path
gem5_root = os.path.join(os.path.dirname(__file__), '..')
sys.path.insert(0, gem5_root)

import m5
from m5.objects import *

def create_simple_system(weights_file):
    """Create a minimal system with Mockingjay on L2."""

    # System
    system = System()
    system.clk_domain = SrcClockDomain(clock='1GHz', voltage_domain=VoltageDomain())
    system.mem_mode = 'timing'
    system.mem_ranges = [AddrRange('512MB')]

    # CPU
    system.cpu = DerivO3CPU()

    # L1 I-cache (LRU)
    system.cpu.icache = Cache(
        size='32kB',
        assoc=8,
        tag_latency=1,
        data_latency=1,
        response_latency=1,
        mshrs=4,
        tgts_per_mshr=20
    )
    system.cpu.icache.replacement_policy = LRURP()

    # L1 D-cache (LRU)
    system.cpu.dcache = Cache(
        size='32kB',
        assoc=8,
        tag_latency=1,
        data_latency=1,
        response_latency=1,
        mshrs=4,
        tgts_per_mshr=20
    )
    system.cpu.dcache.replacement_policy = LRURP()

    # L2 cache (Mockingjay)
    system.l2 = Cache(
        size='256kB',
        assoc=16,
        tag_latency=10,
        data_latency=10,
        response_latency=1,
        mshrs=20,
        tgts_per_mshr=12
    )

    print(f"[Mockingjay Test] Creating MockingjayRP with weights: {weights_file}")
    system.l2.replacement_policy = MockingjayRP(
        weights_file=weights_file,
        enable_online_learning=False
    )

    # Connect L1 to CPU
    system.cpu.icache_port = system.cpu.icache.cpu_side
    system.cpu.dcache_port = system.cpu.dcache.cpu_side

    # L2 bus
    system.l2bus = L2XBar()
    system.cpu.icache.mem_side = system.l2bus.cpu_side_ports
    system.cpu.dcache.mem_side = system.l2bus.cpu_side_ports
    system.l2.cpu_side = system.l2bus.mem_side_ports

    # Memory bus
    system.membus = SystemXBar()
    system.l2.mem_side = system.membus.cpu_side_ports

    # Memory controller
    system.mem_ctrl = MemCtrl()
    system.mem_ctrl.dram = DDR3_1600_8x8()
    system.mem_ctrl.dram.range = system.mem_ranges[0]
    system.mem_ctrl.port = system.membus.mem_side_ports

    # Interrupt controller
    system.cpu.createInterruptController()

    # System port
    system.system_port = system.membus.cpu_side_ports

    return system

def main():
    # Parse arguments
    weights_file = 'configs/mockingjay/weights_trained.json'
    binary = 'benchmarks/smoky/dhrystone.riscv'

    if len(sys.argv) > 1:
        weights_file = sys.argv[1]
    if len(sys.argv) > 2:
        binary = sys.argv[2]

    # Check files exist
    if not os.path.exists(weights_file):
        print(f"ERROR: Weights file not found: {weights_file}")
        print(f"Available weights files:")
        for f in ['configs/mockingjay/weights_random.json',
                  'configs/mockingjay/weights_lru_like.json',
                  'configs/mockingjay/weights_trained.json']:
            if os.path.exists(f):
                print(f"  - {f}")
        return 1

    if not os.path.exists(binary):
        print(f"ERROR: Binary not found: {binary}")
        return 1

    print("=" * 70)
    print("Mockingjay Replacement Policy Test")
    print("=" * 70)
    print(f"Weights file: {weights_file}")
    print(f"Binary: {binary}")
    print("-" * 70)

    # Create system
    system = create_simple_system(weights_file)

    # Set up process
    process = Process()
    process.cmd = [binary]
    system.cpu.workload = process
    system.cpu.createThreads()

    # Instantiate
    root = Root(full_system=False, system=system)
    m5.instantiate()

    print("[Mockingjay Test] Starting simulation...")
    print("-" * 70)

    # Run simulation
    exit_event = m5.simulate()

    print("-" * 70)
    print(f"[Mockingjay Test] Simulation finished: {exit_event.getCause()}")
    print("=" * 70)

    # Print some stats
    print("\nKey Statistics:")
    print(f"Simulated ticks: {m5.curTick()}")
    print(f"Simulated seconds: {m5.curTick() / 1e12:.6f}s")

    print("\n✅ Mockingjay test completed successfully!")
    print("Check m5out/stats.txt for detailed statistics")
    print("=" * 70)

    return 0

if __name__ == '__main__':
    sys.exit(main())
