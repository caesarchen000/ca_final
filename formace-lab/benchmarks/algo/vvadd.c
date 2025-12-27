// Vector Add - Streaming/Prefetch friendly
// Linear memory access pattern, ideal for GHB prefetcher

#include <stdio.h>

#define VECTOR_SIZE 8192

int a[VECTOR_SIZE];
int b[VECTOR_SIZE];
int c[VECTOR_SIZE];

int main() {
    printf("Vector Add of %d elements\n", VECTOR_SIZE);

    // Initialize vectors
    for (int i = 0; i < VECTOR_SIZE; i++) {
        a[i] = i;
        b[i] = VECTOR_SIZE - i;
    }

    // Vector addition
    for (int i = 0; i < VECTOR_SIZE; i++) {
        c[i] = a[i] + b[i];
    }

    // Checksum
    int sum = 0;
    for (int i = 0; i < VECTOR_SIZE; i++) {
        sum += c[i];
    }

    printf("Checksum: %d\n", sum);
    return 0;
}
