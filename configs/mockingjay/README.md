# Mockingjay ML-Based Cache Replacement Policy

## Overview

Mockingjay is a lightweight machine learning-based cache replacement policy for gem5 that uses a simple linear model to predict which cache lines should be evicted. It extracts features from cache access patterns and uses learned weights to make eviction decisions.

## Implementation Location

- **Header**: `/src/mem/cache/replacement_policies/mockingjay.hh`
- **Implementation**: `/src/mem/cache/replacement_policies/mockingjay.cc`
- **Python Config**: `/src/mem/cache/replacement_policies/ReplacementPolicies.py`
- **Weight Files**: `/configs/mockingjay/weights_*.json`

## Features

### Extracted Features (per cache line)

1. **PC Hash** (0-1): Hash of the program counter that accessed this line
   - Captures spatial locality and access patterns
   - Normalized using modulo 1024

2. **Age** (0-1): Time since the cache line was inserted
   - Older lines may be stale and less likely to be reused
   - Logarithmically normalized

3. **Access Count** (0-1): Number of times the line has been accessed
   - Frequently accessed lines should be protected
   - Uses negative weight to reduce eviction priority for hot data
   - Logarithmically normalized

4. **Reuse Distance** (0-1): Number of cache accesses since last use
   - Larger distance suggests lower probability of reuse
   - Logarithmically normalized

### Linear Model

The eviction priority for each cache line is computed as:

```
priority = w1 * pc_hash + w2 * age + w3 * access_count + w4 * reuse_distance + bias
```

**Higher priority = more likely to evict**

### Online Learning (Optional)

When enabled, the policy tracks evicted cache lines and learns from re-reference patterns:

- Maintains a 64-entry eviction tracking table
- When an evicted line is re-accessed, updates weights using gradient descent
- Target: Lines that are quickly re-accessed should have lower eviction priority
- Learning rate: Configurable (default 0.001)

## Configuration Files

### 1. weights_random.json
Random initialization for online learning experiments.

**Use case**: When you want the model to learn from scratch during simulation.

```json
{
  "features": [
    {"name": "pc_hash", "weight": 0.15},
    {"name": "age", "weight": 0.22},
    {"name": "access_count", "weight": -0.18},
    {"name": "reuse_distance", "weight": 0.25}
  ],
  "bias": 0.05,
  "enable_online_learning": true
}
```

### 2. weights_lru_like.json
Mimics traditional LRU behavior for comparison.

**Use case**: Baseline comparison to understand how Mockingjay relates to LRU.

```json
{
  "features": [
    {"name": "pc_hash", "weight": 0.05},
    {"name": "age", "weight": 0.80},  // HIGH - makes it LRU-like
    {"name": "access_count", "weight": -0.10},
    {"name": "reuse_distance", "weight": 0.15}
  ],
  "bias": 0.0,
  "enable_online_learning": false
}
```

### 3. weights_trained.json
Pre-trained weights for general-purpose workloads.

**Use case**: Best overall performance for mixed workloads.

```json
{
  "features": [
    {"name": "pc_hash", "weight": 0.28},
    {"name": "age", "weight": 0.42},
    {"name": "access_count", "weight": -0.35},
    {"name": "reuse_distance", "weight": 0.50}  // Strongest predictor
  ],
  "bias": 0.02,
  "enable_online_learning": false
}
```

## Usage in gem5 Configurations

### Basic Usage

```python
from m5.objects import MockingjayRP

# Create cache with Mockingjay replacement policy
cache = Cache()
cache.size = '256kB'
cache.assoc = 16
cache.replacement_policy = MockingjayRP()
```

### With Weight File

```python
# Use pre-trained weights
cache.replacement_policy = MockingjayRP(
    weights_file='configs/mockingjay/weights_trained.json',
    enable_online_learning=False
)
```

### With Online Learning

```python
# Enable online learning
cache.replacement_policy = MockingjayRP(
    weights_file='configs/mockingjay/weights_random.json',
    enable_online_learning=True,
    learning_rate=0.001
)
```

### Command Line Example

```bash
# Build gem5 (if not already built)
cd /path/to/gem5
scons build/RISCV/gem5.opt -j8

# Run with Mockingjay (example - modify your config script)
./build/RISCV/gem5.opt configs/your_config.py \
    --replacement-policy=mockingjay \
    --weights-file=configs/mockingjay/weights_trained.json
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `weights_file` | String | "" | Path to JSON file with model weights. Empty string uses defaults. |
| `learning_rate` | Float | 0.001 | Learning rate for gradient descent in online learning. |
| `enable_online_learning` | Bool | False | Enable/disable online learning from eviction feedback. |

## Performance Characteristics

### Memory Overhead

Per cache line:
- PC: 8 bytes (Addr)
- Insert tick: 8 bytes (Tick)
- Last touch tick: 8 bytes (Tick)
- Access count: 4 bytes (uint32_t)
- Reuse distance: 8 bytes (uint64_t)
- Priority: 8 bytes (double)

**Total: 44 bytes per cache line**

Global state:
- 4 weights: 32 bytes (4 × double)
- 1 bias: 8 bytes (double)
- Eviction table: ~2KB (64 entries × 32 bytes)

### Computational Overhead

**On cache access (touch)**:
- Feature computation: 4 floating-point operations
- Linear model: 5 multiplications + 4 additions
- ~10-15 FP operations total

**On eviction**:
- Find max priority: O(associativity) comparisons
- Track eviction: O(1) table insert
- Weight update (if learning): ~20 FP operations

## Design Decisions

### Why Linear Model?

1. **Simplicity**: Easy to understand and implement for teaching purposes
2. **Efficiency**: Very low computational overhead
3. **Interpretability**: Weight magnitudes directly show feature importance
4. **Sufficient**: Linear models can achieve good performance for cache replacement

### Why These Features?

1. **PC Hash**: Captures program locality and access patterns
2. **Age**: Proven important in LRU and its variants
3. **Access Count**: Protects frequently used data (hot blocks)
4. **Reuse Distance**: Strong predictor of future reuse in many workloads

### Why Logarithmic Normalization?

Cache metrics often follow power-law distributions. Logarithmic scaling:
- Compresses large values to prevent feature domination
- Provides better numerical stability
- Improves gradient descent convergence

## Comparison with Other Policies

| Policy | Storage | Computation | Adaptivity | Performance |
|--------|---------|-------------|------------|-------------|
| LRU | Low (1 timestamp) | O(assoc) | None | Good |
| Random | None | O(1) | None | Poor |
| RRIP | Low (2-3 bits) | O(assoc) | Limited | Good |
| **Mockingjay** | Medium (44B) | O(assoc) | High (learning) | Very Good |

## Debugging

Enable cache replacement debug output:

```bash
./build/RISCV/gem5.opt --debug-flags=CacheRepl configs/your_config.py
```

This will show:
- Initialization with loaded weights
- Weight updates during online learning
- Eviction decisions (if verbose)

## Testing and Validation

### Sanity Check: LRU Behavior

Set weights to simulate LRU:
```json
{"age": 1.0, "pc_hash": 0.0, "access_count": 0.0, "reuse_distance": 0.0}
```

This should produce similar miss rates to standard LRU.

### Online Learning Validation

1. Start with random weights
2. Enable online learning
3. Run for extended period
4. Check that weights converge to reasonable values
5. Verify improved miss rates over time

## Future Enhancements

Possible extensions for student projects:

1. **More features**: Add spatial locality, stride patterns, etc.
2. **Non-linear models**: Neural networks, decision trees
3. **Specialized learning**: Different weights for different workload phases
4. **Multi-level optimization**: Coordinate replacement across cache levels
5. **Hardware feasibility**: Analyze implementation cost and timing

## References

This implementation is inspired by:

1. **Hawkeye** (ISCA 2016): Learning-based cache replacement using PC-based prediction
2. **Mockingjay** (MICRO 2018): Lightweight ML for cache replacement
3. **Perceptron-based** policies: Early work on ML for caching

## Contact and Support

For questions about this implementation, please refer to:
- gem5 documentation: https://www.gem5.org/documentation/
- gem5 mailing list: gem5-users@gem5.org

---

**Note**: This is a teaching implementation designed for clarity and educational value. Production ML-based cache replacement policies may use more sophisticated features and models.
