# Makefile for cache replacement policy microbenchmarks

CC = riscv64-linux-gnu-gcc
CFLAGS = -O2 -static -march=rv64g -mabi=lp64d
LDFLAGS = -static

TARGETS = cache_thrash.riscv

.PHONY: all clean

all: $(TARGETS)

cache_thrash.riscv: cache_thrash.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS) *.o
