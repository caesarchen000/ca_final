// Towers of Hanoi - Recursive, branch-heavy
// Good for testing branch predictor with function calls

#include <stdio.h>

int move_count = 0;

void move_disk(int from, int to) {
    move_count++;
    // Simulated move - don't print to avoid I/O overhead
}

void hanoi(int n, int from, int to, int aux) {
    if (n == 1) {
        move_disk(from, to);
        return;
    }
    hanoi(n - 1, from, aux, to);
    move_disk(from, to);
    hanoi(n - 1, aux, to, from);
}

int main() {
    int disks = 18;  // 2^18 - 1 = 262,143 moves
    printf("Towers of Hanoi with %d disks\n", disks);

    move_count = 0;
    hanoi(disks, 1, 3, 2);

    printf("Total moves: %d\n", move_count);
    return 0;
}
