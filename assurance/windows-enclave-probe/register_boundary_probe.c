/* Public sentinels only. OS guards/residency and enclave calls are stubbed.
 * This measures wrapper register behavior, NOT production secret disclosure. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

DWORD ProbeAvx, ProbeConcurrent, ProbeDeny, ProbeBodyCalls, ProbeFinishCalls;
DWORD ProbeRestoreFail;
ULONG_PTR ProbeGpr[6], ProbeRbx;
unsigned char ProbeNonvolatile[10][32];
unsigned char ProbePoison[32], ProbeFinish[6][32], ProbeReturn[6][32];
unsigned char ProbeBody[6][32], ProbeRestore[6][32];
unsigned char ProbeZero[32]; /* Measurement negative control, never secret data. */
ULONG_PTR ProbeSlot[2], PublicLockedLow, PublicLockedHigh;
extern ULONG_PTR ProbeRun(void);

static void vectors(unsigned char value[][32], size_t count, size_t width) {
    size_t reg, byte;
    putchar('[');
    for (reg = 0; reg < count; ++reg) {
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
    size_t width, reg;
    if (argc != 6 || (strcmp(argv[1], "sequential") && strcmp(argv[1], "concurrent")) ||
        (strcmp(argv[2], "sse2") && strcmp(argv[2], "avx")) ||
        (strcmp(argv[3], "admit") && strcmp(argv[3], "deny")) ||
        (strcmp(argv[4], "90") && strcmp(argv[4], "165")) ||
        (strcmp(argv[5], "restore-ok") && strcmp(argv[5], "restore-fail"))) return 2;
    ProbeConcurrent = strcmp(argv[1], "concurrent") == 0;
    ProbeAvx = strcmp(argv[2], "avx") == 0;
    ProbeDeny = strcmp(argv[3], "deny") == 0;
    ProbeRestoreFail = strcmp(argv[5], "restore-fail") == 0;
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
    vectors(ProbeFinish, 6, width);
    printf(",\"returned\":");
    vectors(ProbeReturn, 6, width);
    printf(",\"body\":");
    vectors(ProbeBody, 6, width);
    printf(",\"restore_poison\":");
    vectors(ProbeRestore, 6, width);
    printf(",\"restore\":\"%s\",\"nonvolatile\":", argv[5]);
    vectors(ProbeNonvolatile, 10, width);
    printf(",\"rbx\":%llu,\"gpr\":[", (unsigned long long)ProbeRbx);
    for (reg = 0; reg < 6; ++reg) printf("%s%llu", reg ? "," : "", (unsigned long long)ProbeGpr[reg]);
    puts("]}");
    return 0;
}
