/* Fixed synchronous SHA-2 batch transport. All cryptography remains first-party Rust. */
#include "window_retained.c"
static ULONG_PTR sha2_batch_source, sha2_batch_report[7];
ULONG_PTR PublicSha2BatchSource(void) { return active && retained_call ? sha2_batch_source : 0; }
int PublicSha2BatchInput(ULONG_PTR kind, unsigned char* destination, ULONG_PTR source, SIZE_T size) {
    ULONG_PTR address = (ULONG_PTR)destination;
    int result;
    if (!active || !retained_call || kind > 1 || address < PublicLockedLow ||
        address > PublicLockedHigh || size > PublicLockedHigh-address || size > 1024 ||
        (kind == 0 && (size != 128 || sha2_batch_report[3] != 0)) ||
        (kind == 1 && (size == 0 || sha2_batch_report[3] != 1 || sha2_batch_report[4] != 0))) { return E_FAIL; }
    result = EnclaveCopyIntoEnclave(destination, (const void*)source, size);
    if (result == S_OK) { sha2_batch_report[3+kind] = 1; }
    else { sha2_batch_report[6] = 1; }
    return result;
}
int PublicSha2BatchOutput(const unsigned char* source, SIZE_T size) {
    int result;
    if (!active || !retained_call || !retained_live || retained_operation != 85 ||
        !retained_output || size != 512 || sha2_batch_report[5] != 0) { return E_FAIL; }
    result = size == 0 ? S_OK : EnclaveCopyOutOfEnclave((void*)retained_output, source, size);
    if (result == S_OK) { sha2_batch_report[5] = 1; }
    else { sha2_batch_report[6] = 1; }
    return result;
}
int PublicSha2BatchObserve(ULONG_PTR header, ULONG_PTR payload, ULONG_PTR clear) {
    if (!active || !retained_call) { return 0; }
    sha2_batch_report[0]=header; sha2_batch_report[1]=payload; sha2_batch_report[2]=clear;
    return 1;
}
__declspec(dllexport) void* CALLBACK PublicSha2BatchInputSource(void* context) {
    SIZE_T i;
    if (active || retained_call) { return 0; }
    sha2_batch_source = (ULONG_PTR)context;
    for(i=0;i<7;++i) { sha2_batch_report[i]=0; }
    return (void*)1;
}
__declspec(dllexport) void* CALLBACK PublicSha2BatchControl(void* context) {
    ULONG_PTR word = (ULONG_PTR)context;
    if (active || retained_call || word < 16 || word >= 23) { return 0; }
    return (void*)sha2_batch_report[word-16];
}
