// Binary Search - Branch prediction test
// Predictable branches but pattern depends on data

#include <stdio.h>

#define ARRAY_SIZE 4096

int arr[ARRAY_SIZE];

int binary_search(int target) {
    int left = 0;
    int right = ARRAY_SIZE - 1;

    while (left <= right) {
        int mid = left + (right - left) / 2;

        if (arr[mid] == target) {
            return mid;
        }

        if (arr[mid] < target) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    return -1;
}

int main() {
    printf("Binary Search on array of %d elements\n", ARRAY_SIZE);

    // Initialize sorted array
    for (int i = 0; i < ARRAY_SIZE; i++) {
        arr[i] = i * 2;
    }

    // Perform many searches
    int found_count = 0;
    for (int i = 0; i < 10000; i++) {
        int target = (i * 13 + 7) % (ARRAY_SIZE * 2);
        int result = binary_search(target);
        if (result != -1) {
            found_count++;
        }
    }

    printf("Found count: %d\n", found_count);
    return 0;
}
