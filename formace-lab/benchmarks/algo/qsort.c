// Quick Sort - Branch prediction intensive
// Lots of conditional branches, good for TAGE testing

#include <stdio.h>
#include <stdlib.h>

#define ARRAY_SIZE 2048

int arr[ARRAY_SIZE];

void swap(int* a, int* b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

int partition(int low, int high) {
    int pivot = arr[high];
    int i = low - 1;

    for (int j = low; j < high; j++) {
        if (arr[j] < pivot) {
            i++;
            swap(&arr[i], &arr[j]);
        }
    }
    swap(&arr[i + 1], &arr[high]);
    return i + 1;
}

void quicksort(int low, int high) {
    if (low < high) {
        int pi = partition(low, high);
        quicksort(low, pi - 1);
        quicksort(pi + 1, high);
    }
}

int main() {
    printf("Quick Sort of %d elements\n", ARRAY_SIZE);

    // Initialize with pseudo-random data
    for (int i = 0; i < ARRAY_SIZE; i++) {
        arr[i] = (i * 7919 + 1337) % 10000;
    }

    quicksort(0, ARRAY_SIZE - 1);

    // Verify sorted and print checksum
    int is_sorted = 1;
    int sum = 0;
    for (int i = 0; i < ARRAY_SIZE - 1; i++) {
        if (arr[i] > arr[i + 1]) {
            is_sorted = 0;
        }
        sum += arr[i];
    }
    sum += arr[ARRAY_SIZE - 1];

    printf("Sorted: %s, Checksum: %d\n", is_sorted ? "Yes" : "No", sum);
    return 0;
}
