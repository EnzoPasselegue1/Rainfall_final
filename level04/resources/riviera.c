#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define INPUT_SIZE 256
#define LOG_ENTRIES 8
#define TAG_SIZE 32

typedef struct {
    unsigned int seq;
    unsigned int level;
    char tag[TAG_SIZE];
    char message[INPUT_SIZE];
} log_entry_t;

static log_entry_t log_buf[LOG_ENTRIES];
static unsigned int log_seq = 0;
static unsigned int access_level = 0;

static void init_logger(void)
{
    memset(log_buf, 0, sizeof(log_buf));
    log_seq = 0;
    access_level = 1;
}

static void print_banner(void)
{
    printf("\033[0;32m");
    printf("  [RIVIERA] What you see is not what is.\n");
    printf("  [RIVIERA] Holographic logging system v1.9\n");
    printf("\033[0m");
}

static void log_message(const char *tag, const char *msg)
{
    unsigned int idx = log_seq % LOG_ENTRIES;
    log_buf[idx].seq = log_seq++;
    log_buf[idx].level = access_level;
    strncpy(log_buf[idx].tag, tag, TAG_SIZE - 1);
    strncpy(log_buf[idx].message, msg, INPUT_SIZE - 1);
}

static void display_entry(unsigned int idx)
{
    if (idx >= LOG_ENTRIES)
        return;
    printf("[RIVIERA] [%u] tag=", log_buf[idx].seq);
    printf(log_buf[idx].tag);
    printf(" msg=%s\n", log_buf[idx].message);
}

static void handle_input(void)
{
    char tag[TAG_SIZE];
    char msg[INPUT_SIZE];

    printf("[RIVIERA] Tag: ");
    fflush(stdout);
    fgets(tag, TAG_SIZE, stdin);
    tag[strcspn(tag, "\n")] = '\0';

    printf("[RIVIERA] Message: ");
    fflush(stdout);
    fgets(msg, INPUT_SIZE, stdin);
    msg[strcspn(msg, "\n")] = '\0';

    log_message(tag, msg);
    display_entry((log_seq - 1) % LOG_ENTRIES);
}

static void flush_log(void)
{
    for (unsigned int i = 0; i < LOG_ENTRIES && i < log_seq; i++)
        display_entry(i);
}

int main(void)
{
    init_logger();
    print_banner();
    handle_input();
    flush_log();
    return 0;
}
