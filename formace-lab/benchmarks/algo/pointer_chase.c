// Pointer Chase - Cache miss intensive
// Random access pattern, bad for prefetching, stresses cache replacement

#include <stdio.h>
#include <stdlib.h>

#define LIST_SIZE 1024

typedef struct Node {
    int data;
    struct Node* next;
} Node;

Node nodes[LIST_SIZE];

int main() {
    printf("Pointer Chase with %d nodes\n", LIST_SIZE);

    // Create randomized linked list
    int indices[LIST_SIZE];
    for (int i = 0; i < LIST_SIZE; i++) {
        indices[i] = i;
        nodes[i].data = i;
    }

    // Fisher-Yates shuffle for random order
    for (int i = LIST_SIZE - 1; i > 0; i--) {
        int j = (i * 7919 + 1337) % (i + 1);
        int temp = indices[i];
        indices[i] = indices[j];
        indices[j] = temp;
    }

    // Link nodes in shuffled order
    for (int i = 0; i < LIST_SIZE - 1; i++) {
        nodes[indices[i]].next = &nodes[indices[i + 1]];
    }
    nodes[indices[LIST_SIZE - 1]].next = NULL;

    // Chase pointers multiple times
    int iterations = 100;
    int sum = 0;
    for (int iter = 0; iter < iterations; iter++) {
        Node* current = &nodes[indices[0]];
        while (current != NULL) {
            sum += current->data;
            current = current->next;
        }
    }

    printf("Checksum: %d\n", sum);
    return 0;
}
