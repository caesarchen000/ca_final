# Makefile for simple RISC-V benchmarks for gem5 SE mode
# Uses standard riscv64-linux-gnu-gcc (same as hello.riscv)

CC = riscv64-linux-gnu-gcc
CFLAGS = -O2 -static
# Use -O2 for realistic code generation, -static for SE mode

BENCHMARKS = mm qsort vvadd stream towers pointer_chase binary_search

BINARIES = $(addsuffix .riscv, $(BENCHMARKS))

.PHONY: all clean list

all: $(BINARIES)

%.riscv: %.c
	@echo "Compiling $< -> $@"
	$(CC) $(CFLAGS) $< -o $@
	@echo "  Binary size: $$(stat -c%s $@) bytes"
	@echo "  File type: $$(file $@ | cut -d: -f2)"

clean:
	rm -f $(BINARIES)

list:
	@echo "Available benchmarks:"
	@echo "  mm.riscv           - Matrix Multiply (cache/prefetch test)"
	@echo "  qsort.riscv        - Quick Sort (branch prediction test)"
	@echo "  vvadd.riscv        - Vector Add (streaming/prefetch test)"
	@echo "  stream.riscv       - Stream benchmark (memory bandwidth)"
	@echo "  towers.riscv       - Towers of Hanoi (recursive/branch)"
	@echo "  pointer_chase.riscv - Pointer chasing (cache miss test)"
	@echo "  binary_search.riscv - Binary search (branch test)"

help:
	@echo "Usage:"
	@echo "  make           - Compile all benchmarks"
	@echo "  make mm.riscv  - Compile specific benchmark"
	@echo "  make clean     - Remove all binaries"
	@echo "  make list      - List all benchmarks with descriptions"
	@echo ""
	@echo "Requirements:"
	@echo "  - riscv64-linux-gnu-gcc (RISC-V cross compiler)"
	@echo ""
	@echo "Run with gem5:"
	@echo "  ./run_demo.sh --binary benchmarks/demo/simple-benchmarks/mm.riscv"
