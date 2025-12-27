# Mockingjay ML-Based Cache Replacement Policy - Implementation Summary

## Project Overview

This implementation provides a complete, working ML-based cache replacement policy for gem5 called "Mockingjay". It uses a lightweight linear model to predict which cache lines should be evicted based on multiple features extracted from cache access patterns.

## Files Created

### Core Implementation (C++)

1. **`/src/mem/cache/replacement_policies/mockingjay.hh`** (211 lines)
   - Header file with class declaration
   - Defines `MockingjayReplData` structure for per-line metadata
   - Declares eviction tracking table for online learning
   - Feature computation and priority calculation methods

2. **`/src/mem/cache/replacement_policies/mockingjay.cc`** (525 lines)
   - Complete implementation of the Mockingjay policy
   - JSON weight file parsing (simple, no external dependencies)
   - Feature extraction and normalization
   - Linear model computation
   - Online learning with gradient descent
   - Eviction tracking table management

### Python Configuration

3. **`/src/mem/cache/replacement_policies/ReplacementPolicies.py`** (Modified)
   - Added `MockingjayRP` class definition
   - Parameters: `weights_file`, `learning_rate`, `enable_online_learning`

4. **`/src/mem/cache/replacement_policies/SConscript`** (Modified)
   - Added `MockingjayRP` to SimObject list
   - Added `mockingjay.cc` to Source list

### Weight Configuration Files

5. **`/configs/mockingjay/weights_random.json`**
   - Random initialization for online learning experiments
   - Enables online learning by default

6. **`/configs/mockingjay/weights_lru_like.json`**
   - Mimics LRU behavior (high age weight = 0.80)
   - Useful for baseline comparison

7. **`/configs/mockingjay/weights_trained.json`**
   - Balanced weights for general-purpose workloads
   - Reuse distance has highest weight (0.50)
   - Access count has strong negative weight (-0.35) to protect hot data

### Documentation and Examples

8. **`/configs/mockingjay/README.md`**
   - Comprehensive documentation
   - Feature descriptions
   - Usage examples
   - Performance characteristics
   - Comparison with other policies

9. **`/configs/mockingjay/example_config.py`**
   - Example showing how to use Mockingjay in configurations
   - Demonstrates different weight configurations
   - Command-line argument handling

10. **`/configs/mockingjay/simple_test.py`**
    - Validation test script
    - Tests instantiation with different configurations
    - Verifies policy works correctly

11. **`/configs/mockingjay/IMPLEMENTATION_SUMMARY.md`** (This file)
    - Project summary and usage guide

## Key Features Implemented

### 1. Feature Extraction (4 features per cache line)

- **PC Hash**: Normalized hash of program counter (0-1 range)
- **Age**: Time since insertion, logarithmically normalized
- **Access Count**: Number of accesses, logarithmically normalized
- **Reuse Distance**: Global access count since last touch

### 2. Linear Model

```
priority = w1 * pc_hash + w2 * age + w3 * access_count + w4 * reuse_distance + bias
```

Higher priority → more likely to evict

### 3. Online Learning

- 64-entry eviction tracking table
- Gradient descent weight updates
- Learns from eviction/re-reference patterns
- Configurable learning rate

### 4. JSON Weight Loading

- Simple JSON parser (no external dependencies)
- Loads weights from external file
- Falls back to defaults if file not found
- Supports all configuration parameters

## Memory Overhead

**Per cache line**: 44 bytes
- PC: 8 bytes
- Insert tick: 8 bytes
- Last touch tick: 8 bytes
- Access count: 4 bytes
- Reuse distance: 8 bytes
- Priority: 8 bytes

**Global state**: ~2 KB
- Model weights: 40 bytes (5 doubles)
- Eviction table: ~2048 bytes (64 entries)

## Compilation and Testing

### Build Status
✓ Successfully compiled with gem5 RISCV build
✓ All C++ code compiles without errors
✓ Python bindings generated correctly
✓ Test script passes all checks

### Build Command
```bash
cd /mnt/storage1/users/ydwu/projects/computer-architecture.v2/2025_Fall/final
scons build/RISCV/gem5.opt -j4
```

### Test Command
```bash
./build/RISCV/gem5.opt configs/mockingjay/simple_test.py
```

### Test Results
```
All tests passed! MockingjayRP is working correctly.
- Basic instantiation: ✓
- With weights file: ✓
- Online learning config: ✓
- Cache integration: ✓
```

## Usage Examples

### Example 1: Basic Usage with Default Weights
```python
from m5.objects import Cache, MockingjayRP

cache = Cache()
cache.size = '256kB'
cache.assoc = 16
cache.replacement_policy = MockingjayRP()
```

### Example 2: Using Pre-Trained Weights
```python
cache.replacement_policy = MockingjayRP(
    weights_file='configs/mockingjay/weights_trained.json',
    enable_online_learning=False
)
```

### Example 3: Online Learning Mode
```python
cache.replacement_policy = MockingjayRP(
    weights_file='configs/mockingjay/weights_random.json',
    enable_online_learning=True,
    learning_rate=0.001
)
```

### Example 4: LRU-like Baseline
```python
cache.replacement_policy = MockingjayRP(
    weights_file='configs/mockingjay/weights_lru_like.json'
)
```

## Design Decisions

### 1. Why a Linear Model?
- **Simplicity**: Easy to understand for teaching
- **Efficiency**: Minimal computational overhead
- **Interpretability**: Weights show feature importance
- **Sufficient**: Can achieve good performance

### 2. Why These Features?
- **PC Hash**: Captures spatial locality
- **Age**: Proven important in LRU variants
- **Access Count**: Identifies hot/cold data
- **Reuse Distance**: Strong predictor in many workloads

### 3. Why Logarithmic Normalization?
- Cache metrics follow power-law distributions
- Prevents feature domination
- Improves numerical stability
- Better gradient descent convergence

### 4. Why 64-Entry Eviction Table?
- Balance between memory overhead and learning effectiveness
- Covers typical working set changes
- Small enough for hardware feasibility studies

## Integration with gem5

The implementation follows gem5's replacement policy framework:

1. **Inherits from `replacement_policy::Base`**
2. **Implements required methods**:
   - `invalidate()`: Reset cache line metadata
   - `touch()`: Update on cache access
   - `reset()`: Initialize on cache fill
   - `getVictim()`: Select eviction candidate
   - `instantiateEntry()`: Create replacement data

3. **Uses gem5 infrastructure**:
   - `DPRINTF` for debug output (CacheRepl flag)
   - `curTick()` for timing
   - `PacketPtr` for PC extraction
   - Python parameter system

## Debug Output

Enable cache replacement debugging:
```bash
./build/RISCV/gem5.opt --debug-flags=CacheRepl configs/your_config.py
```

This shows:
- Weight initialization
- Weight file loading
- Online learning updates
- Eviction decisions

## Performance Expectations

Based on the design:

1. **vs LRU**: Should perform similarly or better on most workloads
2. **vs Random**: Significantly better due to learned patterns
3. **vs RRIP/BRRIP**: Competitive, with potential for better adaptation
4. **With Online Learning**: Improves over time, adapts to workload changes

## Possible Extensions (Student Projects)

1. **Add more features**: Stride patterns, prefetch hints, memory region
2. **Non-linear models**: Perceptron, decision tree, small neural network
3. **Multi-level coordination**: Share information between L1/L2/L3
4. **Workload-specific tuning**: Train on specific benchmark suites
5. **Hardware cost analysis**: Gate count, timing, power estimation

## Known Limitations

1. **No multi-core awareness**: Each cache learns independently
2. **Simple JSON parser**: Only handles basic format
3. **Fixed eviction table size**: Could be made configurable
4. **No weight checkpointing**: Learned weights not saved across runs
5. **No feature scaling adaptation**: Normalization constants are fixed

## Future Work Suggestions

1. Add weight checkpointing to save/restore learned weights
2. Implement adaptive learning rate (decay over time)
3. Add more sophisticated JSON parsing or switch to library
4. Create training harness for offline weight optimization
5. Add performance counter integration for real-time metrics

## Testing Recommendations

For students using this implementation:

1. **Baseline Comparison**: Test against LRU, Random, RRIP
2. **Sensitivity Analysis**: Vary weights, learning rate
3. **Workload Study**: Test on SPEC, PARSEC, custom benchmarks
4. **Online Learning**: Compare fixed vs. adaptive weights
5. **Memory Pressure**: Test with different cache sizes

## Conclusion

This implementation provides a complete, working ML-based cache replacement policy suitable for:
- Computer architecture courses (teaching ML for systems)
- Research projects (baseline for advanced policies)
- Performance studies (comparing traditional vs. ML approaches)

The code is designed for clarity and educational value while maintaining correctness and reasonable performance.

---

**Implementation Date**: December 5, 2025
**gem5 Version**: 25.0.0.1
**Target ISA**: RISCV (works with other ISAs too)
**Status**: ✓ Tested and working
