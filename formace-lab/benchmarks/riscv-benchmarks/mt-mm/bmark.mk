#=======================================================================
# UCB CS250 Makefile fragment for benchmarks
#-----------------------------------------------------------------------
#
# Each benchmark directory should have its own fragment which
# essentially lists what the source files are and how to link them
# into an riscv and/or host executable. All variables should include
# the benchmark name as a prefix so that they are unique.
#

mt_mm_c_src = \
	mt-mm_main.c \
	mt-mm.c \
	syscalls.c \

mt_mm_riscv_src = \
	crt.S \

mt_mm_c_objs     = $(patsubst %.c, %.o, $(mt_mm_c_src))
mt_mm_riscv_objs = $(patsubst %.S, %.o, $(mt_mm_riscv_src))

mt_mm_host_bin = mt-mm.host
$(mt_mm_host_bin) : $(mt_mm_c_src)
	$(HOST_COMP) $^ -o $(mt_mm_host_bin)

mt_mm_riscv_bin = mt-mm.riscv
$(mt_mm_riscv_bin) : $(mt_mm_c_objs) $(mt_mm_riscv_objs)
	$(RISCV_LINK) $(mt_mm_c_objs) $(mt_mm_riscv_objs) -o $(mt_mm_riscv_bin) $(RISCV_LINK_OPTS)

junk += $(mt_mm_c_objs) $(mt_mm_riscv_objs) \
        $(mt_mm_host_bin) $(mt_mm_riscv_bin)
