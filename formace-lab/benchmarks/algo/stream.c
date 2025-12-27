// Stream Benchmark - Memory bandwidth test
// Tests cache hierarchy and prefetching

#include <stdio.h>

#define STREAM_SIZE 4096

double a[STREAM_SIZE];
double b[STREAM_SIZE];
double c[STREAM_SIZE];

int main() {
    printf("Stream benchmark with %d elements\n", STREAM_SIZE);

    // Initialize
    for (int i = 0; i < STREAM_SIZE; i++) {
        a[i] = 1.0;
        b[i] = 2.0;
        c[i] = 0.0;
    }

    // Copy: c = a
    for (int i = 0; i < STREAM_SIZE; i++) {
        c[i] = a[i];
    }

    // Scale: b = scalar * c
    double scalar = 3.0;
    for (int i = 0; i < STREAM_SIZE; i++) {
        b[i] = scalar * c[i];
    }

    // Add: c = a + b
    for (int i = 0; i < STREAM_SIZE; i++) {
        c[i] = a[i] + b[i];
    }

    // Triad: a = b + scalar * c
    for (int i = 0; i < STREAM_SIZE; i++) {
        a[i] = b[i] + scalar * c[i];
    }

    // Checksum
    double sum = 0.0;
    for (int i = 0; i < STREAM_SIZE; i++) {
        sum += a[i] + b[i] + c[i];
    }

    printf("Checksum: %f\n", sum);
    return 0;
}
