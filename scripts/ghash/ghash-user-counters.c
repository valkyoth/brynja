/* Test-only Linux driver. Count only user-mode execution of this thread or
 * its direct, consenting fixture child. No sampling, raw event codes, kernel
 * addresses, elevated permissions or system-wide monitoring. */
#define _GNU_SOURCE
#include <inttypes.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

enum { N = 4 };
static const uint64_t events[N] = {PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
    PERF_COUNT_HW_BRANCH_MISSES, PERF_COUNT_HW_CACHE_REFERENCES, PERF_COUNT_HW_CACHE_MISSES};
static uint64_t ids[N];
static int fds[N];

static void fail(const char *why) { perror(why); exit(1); }
static void reject(const char *why) { fprintf(stderr, "%s\n", why); exit(1); }

static void open_group(pid_t pid) {
    for (int i = 0; i < N; i++) {
        struct perf_event_attr a = {.type = PERF_TYPE_HARDWARE, .size = sizeof(a),
            .config = events[i], .disabled = (i == 0), .exclude_kernel = 1, .exclude_hv = 1,
            .read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID |
                           PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING};
        fds[i] = (int)syscall(SYS_perf_event_open, &a, pid, -1, i ? fds[0] : -1, PERF_FLAG_FD_CLOEXEC);
        if (fds[i] < 0 || ioctl(fds[i], PERF_EVENT_IOC_ID, &ids[i]) < 0) fail("counter group open");
    }
}

static void enable(void) {
    if (ioctl(fds[0], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) < 0) fail("enable");
}
static void disable(void) {
    if (ioctl(fds[0], PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP) < 0) fail("disable");
}
static void report(void) {
    struct { uint64_t nr, enabled, running, pairs[N][2]; } r;
    if (read(fds[0], &r, sizeof(r)) != (ssize_t)sizeof(r)) fail("group read");
    if (r.nr != N || r.enabled == 0 || r.enabled != r.running) reject("incomplete or multiplexed group");
    printf("%" PRIu64 " %" PRIu64, r.enabled, r.running);
    for (int i = 0; i < N; i++) {
        if (r.pairs[i][1] != ids[i]) reject("wrong counter identity");
        printf(" %" PRIu64, r.pairs[i][0]);
    }
    putchar('\n');
}
static void line(FILE *in, const char *expected) {
    char buf[96];
    if (!fgets(buf, sizeof(buf), in) || strcmp(buf, expected)) reject("unexpected fixture response");
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "probe")) {
        /* Synthetic positive control: touch all cache lines in a permuted
         * order. This validates counter availability, not GHASH behavior. */
        size_t len = 1u << 24;
        volatile unsigned char *buf = calloc(len, 1);
        if (!buf) fail("calloc");
        for (size_t i = 0; i < len; i += 64) buf[i] = 1;
        open_group(0);
        enable();
        for (size_t i = 0; i < len / 64; i++) buf[(i * 65537u * 64u) & (len - 1)]++;
        disable();
        report();
        free((void *)buf);
        return 0;
    }
    if (argc != 5) reject("usage: counter probe | counter FIXTURE MODE LABEL PAIR");
    int ctl[2], ack[2];
    if (pipe(ctl) || pipe(ack)) fail("pipe");
    pid_t child = fork();
    if (child < 0) fail("fork");
    if (!child) {
        if (dup2(ctl[1], STDOUT_FILENO) < 0 || dup2(ack[0], STDIN_FILENO) < 0) _exit(126);
        close(ctl[0]); close(ctl[1]); close(ack[0]); close(ack[1]);
        execl(argv[1], argv[1], argv[2], argv[3], argv[4], "/dev/stdout", "/dev/stdin", (char *)0);
        _exit(127);
    }
    close(ctl[1]); close(ack[0]);
    FILE *in = fdopen(ctl[0], "r");
    if (!in) fail("fdopen");
    line(in, "enable\n");
    open_group(child);
    enable();
    if (write(ack[1], "ack\n", 4) != 4) fail("enable ack");
    line(in, "disable\n");
    disable();
    if (write(ack[1], "ack\n", 4) != 4) fail("disable ack");
    line(in, !strcmp(argv[2], "empty") ? "completed 0 native blocks\n" : "completed 4096 native blocks\n");
    close(ack[1]);
    if (fgetc(in) != EOF || ferror(in)) reject("unexpected fixture output");
    fclose(in);
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
        reject("fixture failed");
    report();
    return 0;
}
