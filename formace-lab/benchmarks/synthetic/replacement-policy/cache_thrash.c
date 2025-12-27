/*
 * cache_thrash.c - Replacement Policy Sensitive Microbenchmark
 *
 * This benchmark creates a scenario where cache replacement policies
 * perform differently by accessing more lines than the associativity
 * of a cache set, creating thrashing conditions.
 */

#include <stdio.h>
#include <stdint.h>

#define CACHE_LINE_SIZE 64
#define L1D_SIZE (32 * 1024)
#define L1D_WAYS 8
#define L1D_SETS (L1D_SIZE / (L1D_WAYS * CACHE_LINE_SIZE))  // 64 sets
#define L1D_SET_STRIDE (L1D_SETS * CACHE_LINE_SIZE)         // 4096 bytes

#define L2_SIZE (256 * 1024)
#define L2_WAYS 8
#define L2_SETS (L2_SIZE / (L2_WAYS * CACHE_LINE_SIZE))     // 512 sets
#define L2_SET_STRIDE (L2_SETS * CACHE_LINE_SIZE)           // 32768 bytes

// Number of lines exceeding associativity
#define NUM_LINES_L1 9   // Exceeds L1D 8-way
#define NUM_LINES_L2 10  // Exceeds L2 8-way

// Iteration count optimized for measurable policy differences
#define OUTER_ITERATIONS 100
#define INNER_ITERATIONS 50

volatile char data_l1[NUM_LINES_L1 * L1D_SET_STRIDE];
volatile char data_l2[NUM_LINES_L2 * L2_SET_STRIDE];

void thrash_l1d() {
    for (int outer = 0; outer < OUTER_ITERATIONS; outer++) {
        for (int inner = 0; inner < INNER_ITERATIONS; inner++) {
            for (int i = 0; i < NUM_LINES_L1; i++) {
                data_l1[i * L1D_SET_STRIDE] += 1;
            }
        }
    }
}

void thrash_l2() {
    for (int outer = 0; outer < OUTER_ITERATIONS; outer++) {
        for (int inner = 0; inner < INNER_ITERATIONS; inner++) {
            for (int i = 0; i < NUM_LINES_L2; i++) {
                data_l2[i * L2_SET_STRIDE] += 1;
            }
        }
    }
}

void thrash_combined() {
    for (int outer = 0; outer < OUTER_ITERATIONS; outer++) {
        for (int inner = 0; inner < INNER_ITERATIONS / 2; inner++) {
            for (int i = 0; i < NUM_LINES_L1; i++) {
                data_l1[i * L1D_SET_STRIDE] += 1;
            }
        }
        for (int inner = 0; inner < INNER_ITERATIONS / 2; inner++) {
            for (int i = 0; i < NUM_LINES_L2; i++) {
                data_l2[i * L2_SET_STRIDE] += 1;
            }
        }
    }
}

int main() {
    printf("Cache Replacement Policy Thrashing Benchmark\n");
    printf("============================================\n");
    printf("L1D: %d KB, %d-way, %d sets\n", L1D_SIZE/1024, L1D_WAYS, L1D_SETS);
    printf("L2:  %d KB, %d-way, %d sets\n", L2_SIZE/1024, L2_WAYS, L2_SETS);
    printf("\n");

    printf("Running L1D thrashing...\n");
    thrash_l1d();

    printf("Running L2 thrashing...\n");
    thrash_l2();

    printf("Running combined thrashing...\n");
    thrash_combined();

    uint64_t checksum = 0;
    for (int i = 0; i < NUM_LINES_L1; i++) {
        checksum += data_l1[i * L1D_SET_STRIDE];
    }
    for (int i = 0; i < NUM_LINES_L2; i++) {
        checksum += data_l2[i * L2_SET_STRIDE];
    }

    printf("Complete. Checksum: %llu\n", (unsigned long long)checksum);
    return 0;
}
