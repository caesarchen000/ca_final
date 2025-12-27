#=======================================================================
# UCB CS250 Makefile fragment for benchmarks
#-----------------------------------------------------------------------
#
# Each benchmark directory should have its own fragment which
# essentially lists what the source files are and how to link them
# into an riscv and/or host executable. All variables should include
# the benchmark name as a prefix so that they are unique.
#

vec_csaxpy_c_src = \
	vec_csaxpy_main.c \
	vec_csaxpy.c \
	syscalls.c \

vec_csaxpy_riscv_src = \
	crt.S \
	vec_csaxpy_asm.S

vec_csaxpy_c_objs     = $(patsubst %.c, %.o, $(vec_csaxpy_c_src))
vec_csaxpy_riscv_objs = $(patsubst %.S, %.o, $(vec_csaxpy_riscv_src))

vec_csaxpy_host_bin = vec-csaxpy.host
$(vec_csaxpy_host_bin): $(vec_csaxpy_c_src)
	$(HOST_COMP) $^ -o $(vec_csaxpy_host_bin)

vec_csaxpy_riscv_bin = vec-csaxpy.riscv
$(vec_csaxpy_riscv_bin): $(vec_csaxpy_c_objs) $(vec_csaxpy_riscv_objs)
	$(RISCV_LINK) $(vec_csaxpy_c_objs) $(vec_csaxpy_riscv_objs) -o $(vec_csaxpy_riscv_bin) $(RISCV_LINK_OPTS)

junk += $(vec_csaxpy_c_objs) $(vec_csaxpy_riscv_objs) \
        $(vec_csaxpy_host_bin) $(vec_csaxpy_riscv_bin)
