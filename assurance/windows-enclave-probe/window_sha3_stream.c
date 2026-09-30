/* Fixed synchronous SHA-3 transport. All cryptography remains first-party Rust. */
#include "window_retained.c"
static ULONG_PTR sha3_source, sha3_report[7];
ULONG_PTR PublicSha3Source(void) { return active && retained_call ? sha3_source : 0; }
int PublicSha3Input(ULONG_PTR kind, unsigned char* destination, ULONG_PTR source, SIZE_T size) {
    ULONG_PTR address = (ULONG_PTR)destination;
    int result;
    if (!active || !retained_call || kind > 1 || address < PublicLockedLow ||
        address > PublicLockedHigh || size > PublicLockedHigh-address || size > 1024 ||
        (kind == 0 && (size != 96 || sha3_report[3] != 0)) ||
        (kind == 1 && (size == 0 || sha3_report[3] != 1 || sha3_report[4] != 0))) { return E_FAIL; }
    result = EnclaveCopyIntoEnclave(destination, (const void*)source, size);
    if (result == S_OK) { sha3_report[3+kind] = 1; }
    else { sha3_report[6] = 1; }
    return result;
}
int PublicSha3Output(const unsigned char* source, SIZE_T size) {
    int result;
    if (!active || !retained_call || !retained_live || retained_operation != 25 ||
        !retained_output || size > 1024 || sha3_report[5] != 0) { return E_FAIL; }
    result = size == 0 ? S_OK : EnclaveCopyOutOfEnclave((void*)retained_output, source, size);
    if (result == S_OK) { sha3_report[5] = 1; }
    else { sha3_report[6] = 1; }
    return result;
}
int PublicSha3Observe(ULONG_PTR header, ULONG_PTR payload, ULONG_PTR clear) {
    if (!active || !retained_call) { return 0; }
    sha3_report[0]=header; sha3_report[1]=payload; sha3_report[2]=clear;
    return 1;
}
__declspec(dllexport) void* CALLBACK PublicSha3InputSource(void* context) {
    SIZE_T i;
    if (active || retained_call) { return 0; }
    sha3_source = (ULONG_PTR)context;
    for(i=0;i<7;++i) { sha3_report[i]=0; }
    return (void*)1;
}
__declspec(dllexport) void* CALLBACK PublicSha3Control(void* context) {
    ULONG_PTR word = (ULONG_PTR)context;
    if (active || retained_call || word < 16 || word >= 23) { return 0; }
    return (void*)sha3_report[word-16];
}
