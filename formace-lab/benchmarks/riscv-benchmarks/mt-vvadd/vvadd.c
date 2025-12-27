// See LICENSE for license details.

#include "stdlib.h"
#include <stdio.h>
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define data_t float
//--------------------------------------------------------------------------
// vvadd function

void __attribute__((noinline)) vvadd(int coreid, int ncores, size_t n, const data_t* x, const data_t* y, data_t* z)
{
   size_t i;
   const size_t chunksize = n / ncores;
   const size_t base = coreid * chunksize;
   const size_t chunk_end = MIN(base + chunksize, n);
   const size_t end = (chunk_end + chunksize > n) ? n : chunk_end;

   for (i = base; i < end; i++)
   {
      z[i] = x[i] + y[i];
   }
}
