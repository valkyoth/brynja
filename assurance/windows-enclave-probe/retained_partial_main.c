/* PUBLIC vectors only. Controlled failure AFTER OS prefix copy, not an OS fault. */
#include "native_host.h"
#include <stdio.h>
#include <string.h>

int RetainedInputRun(void*, uint64_t, const unsigned char*, unsigned char*, uint64_t*);
static int run(HOST_INSTANCE* owner, uint64_t op, const unsigned char* input,
               unsigned char* output, uint64_t status) {
    uint64_t report[4] = {0};
    return RetainedInputRun(owner, op, input, output, report) && report[0] == status;
}
static int campaign(const wchar_t* image) {
    HOST_INSTANCE* owner = HostOpen(image);
    LPENCLAVE_ROUTINE partial;
    uint64_t command, kind, cut, header[4], cases = 0;
    ULONG_PTR reply;
    unsigned char input[1024], output[32];
    static const unsigned char abc_digest[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    if (!owner) { return 10; }
    partial = (LPENCLAVE_ROUTINE)GetProcAddress((HMODULE)owner->base, "PublicPartialControl");
    if (!partial) { return 11; }
    memset(input, 0xa5, sizeof(input));
    /* Exact ABI restrictions: no latent accepted malformed fault request. */
    if (!HostCall(partial, 3ull << 32, &reply) || reply != 0 ||
        !HostCall(partial, (1ull << 32) | 33, &reply) || reply != 0 ||
        !HostCall(partial, (2ull << 32) | 1025, &reply) || reply != 0) { return 12; }
    for (kind = 1; kind <= 2; ++kind) {
        for (cut = 0; cut <= (kind == 1 ? 32u : 1024u); ++cut) {
            if (!run(owner, 0, NULL, NULL, 1)) { return 20; }
            command = (kind << 32) | cut;
            if (!HostCall(partial, command, &reply) || reply != 1) { return 21; }
            owner->partial_expected = command;
            header[0] = 4; header[1] = owner->input_epoch;
            header[2] = sizeof(input); header[3] = (uint64_t)(uintptr_t)input;
            memset(output, 0xcc, sizeof(output));
            if (!run(owner, 1, (const unsigned char*)header, output, 121)) { return 22; }
            owner->partial_expected = 0;
            /* Expected error is terminal; a retry must be Quarantined, not a digest. */
            owner->partial_quarantine = TRUE;
            if (!run(owner, 2, NULL, output, 107)) { return 23; }
            owner->partial_quarantine = FALSE;
            for (unsigned i = 0; i < sizeof(output); ++i) { if (output[i] != 0xcc) { return 24; } }
            if (!run(owner, 3, NULL, NULL, 4)) { return 25; }
            ++cases;
        }
    }
    if (cases != 1058) { return 26; }
    /* Injection is one-shot. A later fresh owner in the same enclave works normally. */
    if (!run(owner, 0, NULL, NULL, 1)) { return 30; }
    header[0] = 4; header[1] = owner->input_epoch; header[2] = 3;
    header[3] = (uint64_t)(uintptr_t)"abc";
    if (!run(owner, 1, (const unsigned char*)header, NULL, 2) ||
        !run(owner, 2, NULL, output, 3) || memcmp(output, abc_digest, 32) ||
        !run(owner, 3, NULL, NULL, 4)) { return 31; }
    if (!HostClose(owner)) { return 32; }
    return 0;
}
int wmain(int argc, wchar_t** argv) {
    int result = argc == 2 ? campaign(argv[1]) : 99;
    printf("{\"result\":%d,\"created\":%llu,\"deleted\":%llu,\"calls\":%llu,"
           "\"retained\":%llu,\"cleanup_errors\":%llu}\n", result,
           HostCounter(0), HostCounter(1), HostCounter(2), HostCounter(3), HostCounter(4));
    return result == 0 && HostCounter(0) == 1 && HostCounter(1) == 1 &&
        HostCounter(2) == 4236 && HostCounter(3) == 0 && HostCounter(4) == 0 ? 0 : 97;
}
