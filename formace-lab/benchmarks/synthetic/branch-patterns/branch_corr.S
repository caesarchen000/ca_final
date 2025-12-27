.section .text
.globl _start

_start:
    li s0, 0              # iteration counter
    li s1, 200000         # iterations
    li s2, 0              # correlation flag

loop:
    andi t0, s0, 1
    beqz t0, first_taken

first_not_taken:
    li s2, 0
    j after_first

first_taken:
    li s2, 1

after_first:
    # Second branch outcome depends on first branch result
    beqz s2, second_taken

second_not_taken:
    nop
    j after_second

second_taken:
    nop

after_second:
    addi s0, s0, 1
    blt s0, s1, loop

    li a0, 0
    li a7, 93
    ecall
