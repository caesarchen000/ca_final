# Benchmarks

本目錄包含測試用的 benchmark 程式。

## 設置

首次使用時，運行：

```bash
cd ..  # 返回 formace-lab 根目錄
./setup_benchmarks.sh
```

這會自動下載所需的 benchmark repositories。

## 目錄結構

```
benchmarks/
├── demo/                          # 公開測試用 benchmarks
│   ├── coremark/                  # CoreMark (從 GitHub clone)
│   ├── dhrystone/                 # Dhrystone (從 GitHub clone)
│   ├── riscv-benchmarks/          # RISC-V Benchmarks (從 GitHub clone)
│   └── simple-benchmarks/         # 編譯好的簡單測試（已包含）
│       ├── mm.riscv              # Matrix multiply
│       ├── vvadd.riscv           # Vector add
│       ├── qsort.riscv           # Quick sort
│       ├── stream.riscv          # Stream
│       ├── towers.riscv          # Towers of Hanoi
│       ├── pointer_chase.riscv   # Pointer chase
│       └── binary_search.riscv   # Binary search
└── hidden/                        # 進階測試用 benchmarks
    └── embench-iot/              # Embench-IoT (從 GitHub clone)
```

## Benchmark Sources

- **CoreMark**: https://github.com/eembc/coremark.git
- **Dhrystone**: https://github.com/RISCV-Tools/dhrystone.git
- **RISC-V Benchmarks**: https://github.com/ucb-bar/riscv-benchmarks.git
- **Embench-IoT**: https://github.com/embench/embench-iot.git

## 注意

- `coremark`, `dhrystone`, `riscv-benchmarks`, `embench-iot` 目錄不會被 commit 到 git
- 這些目錄會被 `.gitignore` 忽略
- 每個使用者需要自己運行 `setup_benchmarks.sh` 來下載
- `simple-benchmarks/` 目錄中的編譯好的文件會被 commit
