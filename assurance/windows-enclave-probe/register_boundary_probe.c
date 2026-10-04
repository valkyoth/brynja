/* Public sentinels only. OS guards/residency and enclave calls are stubbed.
 * This measures wrapper register behavior, NOT production secret disclosure. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

DWORD ProbeAvx, ProbeConcurrent, ProbeDeny, ProbeBodyCalls, ProbeFinishCalls;
unsigned char ProbePoison[32], ProbeFinish[6][32], ProbeReturn[6][32];
unsigned char ProbeZero[32]; /* Measurement negative control, never secret data. */
ULONG_PTR ProbeSlot[2], PublicLockedLow, PublicLockedHigh;
extern ULONG_PTR ProbeRun(void);

static void vectors(unsigned char value[6][32], size_t width) {
    size_t reg, byte;
    putchar('[');
    for (reg = 0; reg < 6; ++reg) {
        if (reg != 0) putchar(',');
        putchar('"');
        for (byte = 0; byte < width; ++byte) printf("%02x", (unsigned int)value[reg][byte]);
        putchar('"');
    }
    putchar(']');
}

int main(int argc, char** argv) {
    ULONG_PTR result;
    unsigned int seed;
    size_t width;
    if (argc != 5 || (strcmp(argv[1], "sequential") && strcmp(argv[1], "concurrent")) ||
        (strcmp(argv[2], "sse2") && strcmp(argv[2], "avx")) ||
        (strcmp(argv[3], "admit") && strcmp(argv[3], "deny")) ||
        (strcmp(argv[4], "90") && strcmp(argv[4], "165"))) return 2;
    ProbeConcurrent = strcmp(argv[1], "concurrent") == 0;
    ProbeAvx = strcmp(argv[2], "avx") == 0;
    ProbeDeny = strcmp(argv[3], "deny") == 0;
    /* Windows reports processor AND OS extended-state availability. */
    if (ProbeAvx && !IsProcessorFeaturePresent(PF_AVX_INSTRUCTIONS_AVAILABLE)) return 3;
    seed = (unsigned int)atoi(argv[4]);
    memset(ProbePoison, (int)seed, sizeof(ProbePoison));
    result = ProbeRun();
    width = ProbeAvx ? 32 : 16;
    printf("{\"wrapper\":\"%s\",\"isa\":\"%s\",\"admission\":\"%s\",\"seed\":%u,"
           "\"result\":%llu,\"body_calls\":%lu,\"finish_calls\":%lu,\"finish\":",
           argv[1], argv[2], argv[3], seed, (unsigned long long)result,
           (unsigned long)ProbeBodyCalls, (unsigned long)ProbeFinishCalls);
    vectors(ProbeFinish, width);
    printf(",\"returned\":");
    vectors(ProbeReturn, width);
    puts("}");
    return 0;
}
