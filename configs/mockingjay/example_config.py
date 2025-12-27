#!/usr/bin/env python3
"""
Example configuration script for using Mockingjay replacement policy in gem5.

This script demonstrates how to configure a cache with the Mockingjay
ML-based replacement policy with different weight configurations.

Usage:
    # Use default (random) weights
    gem5 example_config.py

    # Use LRU-like weights
    gem5 example_config.py --weights-config lru_like

    # Use trained weights
    gem5 example_config.py --weights-config trained

    # Enable online learning
    gem5 example_config.py --enable-learning
"""

import argparse
import os
import sys

import m5
from m5.objects import *

# Add path to gem5 configs if needed
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'common'))


def create_mockingjay_policy(weights_config='random', enable_learning=False):
    """
    Create a Mockingjay replacement policy with specified configuration.

    Args:
        weights_config: One of 'random', 'lru_like', or 'trained'
        enable_learning: Enable online learning from eviction feedback

    Returns:
        MockingjayRP object configured with specified weights
    """
    # Determine weights file path
    config_dir = os.path.dirname(os.path.abspath(__file__))
    weights_files = {
        'random': os.path.join(config_dir, 'weights_random.json'),
        'lru_like': os.path.join(config_dir, 'weights_lru_like.json'),
        'trained': os.path.join(config_dir, 'weights_trained.json')
    }

    if weights_config not in weights_files:
        print(f"Error: Unknown weights config '{weights_config}'")
        print(f"Available options: {', '.join(weights_files.keys())}")
        sys.exit(1)

    weights_file = weights_files[weights_config]

    # Verify file exists
    if not os.path.exists(weights_file):
        print(f"Warning: Weights file not found: {weights_file}")
        print("Using default weights built into the policy.")
        weights_file = ""

    # Create the replacement policy
    policy = MockingjayRP()
    policy.weights_file = weights_file
    policy.enable_online_learning = enable_learning

    # Learning rate can be adjusted if needed
    if enable_learning:
        policy.learning_rate = 0.001

    return policy


def create_simple_cache_hierarchy(replacement_policy):
    """
    Create a simple cache hierarchy for testing.

    Args:
        replacement_policy: The replacement policy to use

    Returns:
        Tuple of (l1_dcache, l1_icache, l2_cache)
    """
    # L1 Data Cache
    l1_dcache = Cache()
    l1_dcache.size = '32kB'
    l1_dcache.assoc = 8
    l1_dcache.tag_latency = 1
    l1_dcache.data_latency = 1
    l1_dcache.response_latency = 1
    l1_dcache.mshrs = 16
    l1_dcache.tgts_per_mshr = 20
    l1_dcache.replacement_policy = replacement_policy

    # L1 Instruction Cache
    l1_icache = Cache()
    l1_icache.size = '32kB'
    l1_icache.assoc = 8
    l1_icache.tag_latency = 1
    l1_icache.data_latency = 1
    l1_icache.response_latency = 1
    l1_icache.mshrs = 16
    l1_icache.tgts_per_mshr = 20
    l1_icache.replacement_policy = MockingjayRP()  # Use default for I-cache

    # L2 Cache - use Mockingjay here too
    l2_cache = Cache()
    l2_cache.size = '256kB'
    l2_cache.assoc = 16
    l2_cache.tag_latency = 10
    l2_cache.data_latency = 10
    l2_cache.response_latency = 1
    l2_cache.mshrs = 32
    l2_cache.tgts_per_mshr = 20
    l2_cache.replacement_policy = replacement_policy

    return l1_dcache, l1_icache, l2_cache


def main():
    parser = argparse.ArgumentParser(
        description="Example gem5 configuration with Mockingjay replacement policy"
    )
    parser.add_argument(
        '--weights-config',
        choices=['random', 'lru_like', 'trained'],
        default='random',
        help='Which weight configuration to use (default: random)'
    )
    parser.add_argument(
        '--enable-learning',
        action='store_true',
        help='Enable online learning from eviction feedback'
    )
    parser.add_argument(
        '--cpu-type',
        default='TimingSimpleCPU',
        help='CPU type to use (default: TimingSimpleCPU)'
    )
    parser.add_argument(
        '--benchmark',
        default='hello',
        help='Benchmark binary to run (default: hello)'
    )

    args = parser.parse_args()

    print("=" * 70)
    print("Mockingjay Replacement Policy Example Configuration")
    print("=" * 70)
    print(f"Weights config: {args.weights_config}")
    print(f"Online learning: {'Enabled' if args.enable_learning else 'Disabled'}")
    print(f"CPU type: {args.cpu_type}")
    print("=" * 70)

    # Create the replacement policy
    repl_policy = create_mockingjay_policy(
        weights_config=args.weights_config,
        enable_learning=args.enable_learning
    )

    # Print configuration details
    print(f"\nMockingjay Configuration:")
    print(f"  Weights file: {repl_policy.weights_file}")
    print(f"  Learning rate: {repl_policy.learning_rate}")
    print(f"  Online learning: {repl_policy.enable_online_learning}")
    print()

    # Note: This is a minimal example showing how to create the policy
    # For a complete system simulation, you would need to:
    # 1. Create a full system with CPU, memory, etc.
    # 2. Connect the caches to the CPU and memory bus
    # 3. Set up the workload/benchmark
    # 4. Call m5.instantiate() and run the simulation

    print("Mockingjay replacement policy created successfully!")
    print("\nTo use this in a full simulation, integrate this policy")
    print("into your existing gem5 configuration scripts.")
    print("\nExample usage in your config:")
    print("  cache.replacement_policy = MockingjayRP(")
    print("      weights_file='configs/mockingjay/weights_trained.json',")
    print("      enable_online_learning=False,")
    print("      learning_rate=0.001")
    print("  )")


if __name__ == '__main__':
    main()
