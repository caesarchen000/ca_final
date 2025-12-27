# Mockingjay Quick Start Guide

## 1. Verify Installation

Check that Mockingjay is properly installed:

```bash
cd /mnt/storage1/users/ydwu/projects/computer-architecture.v2/2025_Fall/final
./build/RISCV/gem5.opt configs/mockingjay/simple_test.py
```

Expected output:
```
All tests passed! MockingjayRP is working correctly.
```

## 2. Basic Usage in Your Config

Add to your gem5 configuration file:

```python
from m5.objects import Cache, MockingjayRP

# Create cache with Mockingjay
l1_cache = Cache()
l1_cache.size = '32kB'
l1_cache.assoc = 8
l1_cache.replacement_policy = MockingjayRP(
    weights_file='configs/mockingjay/weights_trained.json'
)
```

## 3. Available Weight Configurations

| Configuration | Use Case | Online Learning |
|---------------|----------|-----------------|
| `weights_random.json` | Learning experiments | Enabled |
| `weights_lru_like.json` | LRU baseline | Disabled |
| `weights_trained.json` | Best general performance | Disabled |

## 4. Common Configurations

### Configuration A: Best Performance (Recommended)
```python
cache.replacement_policy = MockingjayRP(
    weights_file='configs/mockingjay/weights_trained.json',
    enable_online_learning=False
)
```

### Configuration B: Online Learning
```python
cache.replacement_policy = MockingjayRP(
    weights_file='configs/mockingjay/weights_random.json',
    enable_online_learning=True,
    learning_rate=0.001
)
```

### Configuration C: LRU Comparison
```python
cache.replacement_policy = MockingjayRP(
    weights_file='configs/mockingjay/weights_lru_like.json'
)
```

### Configuration D: Default Weights
```python
cache.replacement_policy = MockingjayRP()
# Uses built-in default weights
```

## 5. Enable Debug Output

See what Mockingjay is doing:

```bash
./build/RISCV/gem5.opt --debug-flags=CacheRepl your_config.py
```

## 6. Create Custom Weights

Copy and modify an existing weights file:

```bash
cp configs/mockingjay/weights_trained.json configs/mockingjay/my_weights.json
# Edit my_weights.json with your preferred weights
```

Then use it:
```python
cache.replacement_policy = MockingjayRP(
    weights_file='configs/mockingjay/my_weights.json'
)
```

## 7. Compare with Other Policies

```python
from m5.objects import LRURP, RandomRP, BRRIPRP

# LRU
cache1.replacement_policy = LRURP()

# Random
cache2.replacement_policy = RandomRP()

# BRRIP
cache3.replacement_policy = BRRIPRP()

# Mockingjay
cache4.replacement_policy = MockingjayRP(
    weights_file='configs/mockingjay/weights_trained.json'
)
```

## 8. Typical Workflow

1. Start with trained weights for baseline
2. Compare against LRU and other policies
3. Try online learning for adaptive scenarios
4. Tune weights for your specific workload
5. Measure miss rates and performance

## 9. Troubleshooting

### Problem: "MockingjayRP not found"
**Solution**: Rebuild gem5
```bash
scons build/RISCV/gem5.opt -j4
```

### Problem: Weights file not found
**Solution**: Use absolute path or verify location
```python
import os
weights_path = os.path.join(
    os.path.dirname(__file__),
    '../mockingjay/weights_trained.json'
)
cache.replacement_policy = MockingjayRP(weights_file=weights_path)
```

### Problem: Poor performance
**Solution**: Try different weight configurations or enable learning
```python
# Try LRU-like first
cache.replacement_policy = MockingjayRP(
    weights_file='configs/mockingjay/weights_lru_like.json'
)
```

## 10. Example: Complete Simple System

```python
#!/usr/bin/env python3

import m5
from m5.objects import *

# Create system
system = System()
system.clk_domain = SrcClockDomain()
system.clk_domain.clock = '1GHz'
system.clk_domain.voltage_domain = VoltageDomain()
system.mem_mode = 'timing'

# Create CPU with cache using Mockingjay
system.cpu = TimingSimpleCPU()

# L1 Data Cache with Mockingjay
system.cpu.dcache = Cache()
system.cpu.dcache.size = '64kB'
system.cpu.dcache.assoc = 8
system.cpu.dcache.replacement_policy = MockingjayRP(
    weights_file='configs/mockingjay/weights_trained.json'
)

# L1 Instruction Cache with Mockingjay
system.cpu.icache = Cache()
system.cpu.icache.size = '32kB'
system.cpu.icache.assoc = 8
system.cpu.icache.replacement_policy = MockingjayRP(
    weights_file='configs/mockingjay/weights_trained.json'
)

# ... rest of system setup ...
```

## 11. Performance Metrics

After running simulation, check:

```python
# In your config, add stats dumping
m5.stats.dump()
```

Look for in stats.txt:
- `system.cpu.dcache.overall_miss_rate::total`
- `system.cpu.icache.overall_miss_rate::total`
- Compare with baseline LRU/Random policies

## 12. Advanced: Custom Feature Weights

Understanding the weights:

| Feature | Weight Range | Effect |
|---------|--------------|--------|
| pc_hash | 0.0 - 0.5 | Higher = more PC-locality aware |
| age | 0.0 - 1.0 | Higher = more LRU-like |
| access_count | -0.5 - 0.0 | More negative = stronger hot-data protection |
| reuse_distance | 0.0 - 1.0 | Higher = evict blocks with large reuse distance |

Example: Aggressive hot-data protection
```json
{
  "features": [
    {"name": "pc_hash", "weight": 0.20},
    {"name": "age", "weight": 0.30},
    {"name": "access_count", "weight": -0.60},  // Very negative!
    {"name": "reuse_distance", "weight": 0.40}
  ],
  "bias": 0.0
}
```

## Need Help?

- Read `README.md` for detailed documentation
- Check `IMPLEMENTATION_SUMMARY.md` for technical details
- Run `simple_test.py` to verify installation
- Enable `--debug-flags=CacheRepl` for debugging

Happy experimenting with ML-based cache replacement!
