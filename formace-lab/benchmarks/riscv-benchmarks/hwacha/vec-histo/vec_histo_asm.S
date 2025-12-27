## Hwacha v4 SAXPY ASM code

#include "vec-util.h"

.text

# vector thread asm
.align 3
.globl histo_v
histo_v:
    vpset vp0
    vlw vv0, va0 # bin[i] = input_data[i]
    vsll.vs vv1, vv0, vs1 # offset[i] = bin[i] * 4
    vadd.vs vv0, vv1, vs2 # addr[i] = offset[i] + output_bins
    vamoadd.w.vs vv1, 0(vv0), vs3 # old[i] = *addr[i]++
    vstop
