CC = riscv64-linux-gnu-gcc
ASFLAGS = -O2 -static -nostdlib -nostartfiles

PROGRAMS = branch_corr branch_bias

BINARIES = $(addsuffix .riscv,$(PROGRAMS))

.PHONY: all clean

all: $(BINARIES)

%.riscv: %.S
	$(CC) $(ASFLAGS) $< -o $@

clean:
	rm -f $(BINARIES)
