// Matrix Multiply - Cache and Prefetch intensive
// Small enough to run quickly, large enough to show effects

#include <stdio.h>

#define N 64  // 64x64 matrices for reasonable runtime

int A[N][N];
int B[N][N];
int C[N][N];

void init_matrices() {
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            A[i][j] = i + j;
            B[i][j] = i - j;
            C[i][j] = 0;
        }
    }
}

void matrix_multiply() {
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            for (int k = 0; k < N; k++) {
                C[i][j] += A[i][k] * B[k][j];
            }
        }
    }
}

int main() {
    printf("Matrix Multiply %dx%d\n", N, N);
    init_matrices();
    matrix_multiply();

    // Print checksum to prevent optimization
    int sum = 0;
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            sum += C[i][j];
        }
    }
    printf("Checksum: %d\n", sum);
    return 0;
}
