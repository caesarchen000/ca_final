#include "vec-util.h"
#include "vec_histo.h"

extern char histo_v[];

static inline void vec_setup(void *output_bins)
{
  unsigned long cfg = VCFG(0, 2, 0, 1);
  asm volatile ("vsetcfg %[cfg]" :: [cfg] "r" (cfg));
  asm volatile ("vmcs vs1, %[shift]" :: [shift] "r" (2));
  asm volatile ("vmcs vs2, %[base]" :: [base] "r" (output_bins));
  asm volatile ("vmcs vs3, %[inc]" :: [inc] "r" (1));
}

void vec_histo(int ndata, int nbins, int *input_data, int *output_bins)
{
  int vl;
  vec_setup(output_bins);

  while (ndata > 0) {
    asm volatile ("vsetvl %[vl], %[n]" : [vl] "=r" (vl) : [n] "r" (ndata));
    asm volatile ("vmca va0, %[input]" :: [input] "r" (input_data));
    asm volatile ("vf 0(%[addr])" :: [addr] "r" (histo_v));
    input_data += vl;
    ndata -= vl;
  }

  asm volatile ("fence");
}
