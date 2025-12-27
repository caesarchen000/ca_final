#include "mt_histo.h"
#include "dataset1.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

#define NTHREADS 16

struct histo_data {
    int start;
    int end;
    int nbins;
    int *input_data;
    int *output_bins;
};

int temp_bins[NUM_BINS * 16];

void histo_kernel(int *in_data, int ndata, int *local_bins, int *out_bins, int nbins)
{
    int i, oldsum;

    memset(local_bins, 0, sizeof(int) * nbins);

    for (i = 0; i < ndata; i++) {
        int pos = in_data[i];
        local_bins[pos]++;
    }

    for (i = 0; i < nbins; i++) {
        int *dst;

        if (local_bins[i] == 0)
            continue;

        dst = &out_bins[i];
        asm volatile ("amoadd.w %[oldsum], %[count], (%[dst])" :
                [oldsum] "=r" (oldsum) :
                [count] "r" (local_bins[i]),
                [dst] "r" (dst));
    }
}

void printBins(int *out_bins, int nbins)
{
    int i;

    for (i = 0; i < nbins; i++)
        printf("out_bins[%d] = %d\n", i, out_bins[i]);
}

#define min(a, b) ((a) < (b)) ? (a) : (b)


void thread_entry(int cid, int nc)
{
    int local_data_size = (DATA_SIZE - 1) / nc + 1;
    int start = cid * local_data_size;
    int end = min(start + local_data_size, DATA_SIZE);
    int ret = 0;

    stats(
        histo_kernel(input_data + start, end - start,
		temp_bins + cid * NUM_BINS, output_bins, NUM_BINS);
	barrier(nc),
	1);

#ifdef DEBUG
    // Print out the result
    printArray("results", NUM_BINS, output_bins);
#endif

    // Check the results
    ret = verify(NUM_BINS, output_bins, verify_data);

    exit(ret);
}
