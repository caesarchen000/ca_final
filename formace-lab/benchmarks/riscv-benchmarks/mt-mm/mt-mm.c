// See LICENSE for license details.

#include "common.h"
#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <alloca.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static void mm_naive(size_t m, size_t n, size_t p,
                     t* a, size_t lda, t* b, size_t ldb, t* c, size_t ldc)
{
  for (size_t i = 0; i < m; i++)
  {
    for (size_t j = 0; j < n; j++)
    {
      t s0 = c[i*ldc+j], s1 = 0, s2 = 0, s3 = 0;
      for (size_t k = 0; k < p/4*4; k+=4)
      {
        s0 = fma(a[i*lda+k+0], b[(k+0)*ldb+j], s0);
        s1 = fma(a[i*lda+k+1], b[(k+1)*ldb+j], s1);
        s2 = fma(a[i*lda+k+2], b[(k+2)*ldb+j], s2);
        s3 = fma(a[i*lda+k+3], b[(k+3)*ldb+j], s3);
      }
      for (size_t k = p/4*4; k < p; k++)
        s0 = fma(a[i*lda+k], b[k*ldb+j], s0);
      c[i*ldc+j] = (s0 + s1) + (s2 + s3);
    }
  }
}

static inline void mm_rb(size_t m, size_t n, size_t p,
                         t* a, size_t lda, t* b, size_t ldb, t* c, size_t ldc,
			 int cid, int nc)
{
  size_t mb = m/(RBM*nc)*(RBM*nc), nb = n/RBN*RBN;
  for (size_t i = RBM*cid; i < mb; i += RBM*nc)
  {
    for (size_t j = 0; j < nb; j += RBN)
      kloop(p, a+i*lda, lda, b+j, ldb, c+i*ldc+j, ldc);
    mm_naive(RBM, n - nb, p, a+i*lda, lda, b+nb, ldb, c+i*ldc+nb, ldc);
  }
  if (cid == 0)
    mm_naive(m - mb, n, p, a+mb*lda, lda, b, ldb, c+mb*ldc, ldc);
}

void mm(size_t m, size_t n, size_t p,
        t* a, size_t lda, t* b, size_t ldb, t* c, size_t ldc,
	int cid, int nc)
{
  mm_rb(m, n, p, a, lda, b, ldb, c, ldc, cid, nc);
}
