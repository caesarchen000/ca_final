.section .text
.globl _start

_start:
    li s0, 0              # iteration counter
    li s1, 400000         # iterations

loop_bias:
    addi s0, s0, 1
    andi t0, s0, 63       # Every 64 iterations
    bnez t0, mostly_taken # 63/64 iterations take this branch

rare_path:
    nop                   # branch not taken path
    j after_bias

mostly_taken:
    nop

after_bias:
    blt s0, s1, loop_bias

    li a0, 0
    li a7, 93
    ecall
