#!/usr/bin/env python3
"""
Simple test that can be run with gem5 to verify Mockingjay works.
Run with: ./build/RISCV/gem5.opt configs/mockingjay/simple_test.py
"""

import m5
from m5.objects import *

print("Testing Mockingjay Replacement Policy")
print("=" * 60)

# Test 1: Basic instantiation
print("\n1. Creating basic MockingjayRP...")
try:
    policy1 = MockingjayRP()
    print(f"   SUCCESS - Default configuration:")
    print(f"   - weights_file: '{policy1.weights_file}'")
    print(f"   - learning_rate: {policy1.learning_rate}")
    print(f"   - enable_online_learning: {policy1.enable_online_learning}")
except Exception as e:
    print(f"   FAILED: {e}")
    exit(1)

# Test 2: With weights file
print("\n2. Creating MockingjayRP with weights file...")
try:
    policy2 = MockingjayRP()
    policy2.weights_file = "configs/mockingjay/weights_trained.json"
    policy2.enable_online_learning = False
    print(f"   SUCCESS - Trained weights configuration:")
    print(f"   - weights_file: '{policy2.weights_file}'")
    print(f"   - enable_online_learning: {policy2.enable_online_learning}")
except Exception as e:
    print(f"   FAILED: {e}")
    exit(1)

# Test 3: With online learning
print("\n3. Creating MockingjayRP with online learning...")
try:
    policy3 = MockingjayRP()
    policy3.weights_file = "configs/mockingjay/weights_random.json"
    policy3.enable_online_learning = True
    policy3.learning_rate = 0.001
    print(f"   SUCCESS - Online learning configuration:")
    print(f"   - weights_file: '{policy3.weights_file}'")
    print(f"   - enable_online_learning: {policy3.enable_online_learning}")
    print(f"   - learning_rate: {policy3.learning_rate}")
except Exception as e:
    print(f"   FAILED: {e}")
    exit(1)

# Test 4: Create a cache with Mockingjay
print("\n4. Creating cache with MockingjayRP...")
try:
    cache = Cache()
    cache.size = '64kB'
    cache.assoc = 8
    cache.tag_latency = 1
    cache.data_latency = 1
    cache.response_latency = 1
    cache.mshrs = 16
    cache.tgts_per_mshr = 20
    cache.replacement_policy = MockingjayRP(
        weights_file="configs/mockingjay/weights_trained.json"
    )
    print(f"   SUCCESS - Cache created with Mockingjay:")
    print(f"   - size: {cache.size}")
    print(f"   - assoc: {cache.assoc}")
    print(f"   - replacement_policy: MockingjayRP")
except Exception as e:
    print(f"   FAILED: {e}")
    exit(1)

print("\n" + "=" * 60)
print("All tests passed! MockingjayRP is working correctly.")
print("=" * 60)
print("\nNote: This only tests instantiation. For full simulation")
print("testing, integrate MockingjayRP into your system config.")

# Exit successfully
exit(0)
