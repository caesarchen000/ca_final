#!/usr/bin/env python3
"""
Simple test to verify Mockingjay replacement policy can be instantiated.
This doesn't run a full simulation, just checks that the policy is
properly registered and can be created with different configurations.
"""

import sys
import os

# Add gem5 python path
gem5_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(gem5_root, 'src', 'python'))

try:
    import m5
    from m5.objects import MockingjayRP
except ImportError as e:
    print(f"Error importing gem5: {e}")
    print("\nThis test must be run from a built gem5 environment.")
    print("Try: cd /path/to/gem5 && python3 configs/mockingjay/test_mockingjay.py")
    sys.exit(1)


def test_basic_instantiation():
    """Test basic policy creation."""
    print("Test 1: Basic instantiation...")
    try:
        policy = MockingjayRP()
        print("  ✓ MockingjayRP created successfully")
        print(f"    - weights_file: '{policy.weights_file}'")
        print(f"    - learning_rate: {policy.learning_rate}")
        print(f"    - enable_online_learning: {policy.enable_online_learning}")
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False


def test_with_weights_file():
    """Test policy with weights file."""
    print("\nTest 2: With weights file...")
    try:
        config_dir = os.path.dirname(os.path.abspath(__file__))
        weights_file = os.path.join(config_dir, 'weights_trained.json')

        policy = MockingjayRP()
        policy.weights_file = weights_file
        policy.enable_online_learning = False

        print("  ✓ MockingjayRP created with weights file")
        print(f"    - weights_file: '{policy.weights_file}'")
        print(f"    - enable_online_learning: {policy.enable_online_learning}")

        # Check if file exists
        if os.path.exists(weights_file):
            print(f"    - Weights file exists: {weights_file}")
        else:
            print(f"    - WARNING: Weights file not found: {weights_file}")

        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False


def test_online_learning():
    """Test policy with online learning enabled."""
    print("\nTest 3: Online learning configuration...")
    try:
        config_dir = os.path.dirname(os.path.abspath(__file__))
        weights_file = os.path.join(config_dir, 'weights_random.json')

        policy = MockingjayRP()
        policy.weights_file = weights_file
        policy.enable_online_learning = True
        policy.learning_rate = 0.001

        print("  ✓ MockingjayRP created with online learning")
        print(f"    - weights_file: '{policy.weights_file}'")
        print(f"    - enable_online_learning: {policy.enable_online_learning}")
        print(f"    - learning_rate: {policy.learning_rate}")
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False


def test_all_weight_configs():
    """Test all weight configuration files."""
    print("\nTest 4: All weight configurations...")
    config_dir = os.path.dirname(os.path.abspath(__file__))
    configs = ['weights_random.json', 'weights_lru_like.json', 'weights_trained.json']

    all_passed = True
    for config_name in configs:
        try:
            weights_file = os.path.join(config_dir, config_name)
            policy = MockingjayRP()
            policy.weights_file = weights_file

            exists = os.path.exists(weights_file)
            status = "✓" if exists else "⚠"
            print(f"  {status} {config_name}: {'exists' if exists else 'NOT FOUND'}")

            if not exists:
                all_passed = False
        except Exception as e:
            print(f"  ✗ {config_name}: Failed - {e}")
            all_passed = False

    return all_passed


def main():
    print("=" * 70)
    print("Mockingjay Replacement Policy Tests")
    print("=" * 70)

    results = []
    results.append(test_basic_instantiation())
    results.append(test_with_weights_file())
    results.append(test_online_learning())
    results.append(test_all_weight_configs())

    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")

    if passed == total:
        print("\n✓ All tests passed! Mockingjay replacement policy is ready to use.")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed. Please check the errors above.")
        return 1


if __name__ == '__main__':
    sys.exit(main())
