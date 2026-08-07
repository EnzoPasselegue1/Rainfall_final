#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define QUERY_SIZE 96
#define NODE_COUNT 6
#define MATRIX_DIM 3

typedef struct {
    unsigned int id;
    unsigned int weight;
    unsigned int active;
    char label[16];
} node_t;

static node_t nodes[NODE_COUNT];
static unsigned int matrix[MATRIX_DIM][MATRIX_DIM];

static void init_matrix(void)
{
    static const unsigned int base[MATRIX_DIM][MATRIX_DIM] = {
        {0x1a, 0x2b, 0x3c},
        {0x4d, 0x5e, 0x6f},
        {0x7a, 0x8b, 0x9c}
    };
    memcpy(matrix, base, sizeof(matrix));

    for (unsigned int i = 0; i < NODE_COUNT; i++) {
        nodes[i].id = i;
        nodes[i].weight = i * 7 + 3;
        nodes[i].active = (i % 2 == 0);
        snprintf(nodes[i].label, 16, "N%03u", i);
    }
}

static void print_banner(void)
{
    printf("\033[0;34m");
    printf("  [WINTERMUTE] I am everywhere and nowhere.\n");
    printf("  [WINTERMUTE] Neural query interface active.\n");
    printf("\033[0m");
}

static unsigned int hash_query(const char *q, size_t len)
{
    unsigned int h = 0xdeadbeef;
    for (size_t i = 0; i < len; i++)
        h = (h << 5) ^ (h >> 3) ^ (unsigned int)q[i];
    return h;
}

static void process_matrix(unsigned int seed)
{
    for (unsigned int i = 0; i < MATRIX_DIM; i++)
        for (unsigned int j = 0; j < MATRIX_DIM; j++)
            matrix[i][j] ^= seed;
}

static void run_query(void)
{
    char query[QUERY_SIZE];
    unsigned int h;

    printf("[WINTERMUTE] Query: ");
    fflush(stdout);

    gets(query);

    h = hash_query(query, strlen(query));
    process_matrix(h);

    printf("[WINTERMUTE] Hash: %08x\n", h);
    printf("[WINTERMUTE] Matrix[0][0]: %08x\n", matrix[0][0]);

    for (unsigned int i = 0; i < NODE_COUNT; i++) {
        if (nodes[i].active)
            printf("[WINTERMUTE] Node %s weight=%u\n",
                nodes[i].label, nodes[i].weight);
    }
}

int main(void)
{
    init_matrix();
    print_banner();
    run_query();
    return 0;
}
