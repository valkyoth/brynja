/* Fixed synchronous KMAC transport. All cryptography remains first-party Rust. */
#include "window_retained.c"
static ULONG_PTR kmac_source, kmac_report[7];
ULONG_PTR PublicKmacSource(void) { return active && retained_call ? kmac_source : 0; }
int PublicKmacInput(ULONG_PTR kind, unsigned char* destination, ULONG_PTR source, SIZE_T size) {
    ULONG_PTR address = (ULONG_PTR)destination;
    int result;
    if (!active || !retained_call || kind > 1 || address < PublicLockedLow ||
        address > PublicLockedHigh || size > PublicLockedHigh-address || size > 1024 ||
        (kind == 0 && (size != 96 || kmac_report[3] != 0)) ||
        (kind == 1 && (size == 0 || kmac_report[3] != 1 || kmac_report[4] != 0))) { return E_FAIL; }
    result = EnclaveCopyIntoEnclave(destination, (const void*)source, size);
    if (result == S_OK) { kmac_report[3+kind] = 1; }
    else { kmac_report[6] = 1; }
    return result;
}
int PublicKmacOutput(const unsigned char* source, SIZE_T size) {
    int result;
    if (!active || !retained_call || !retained_live || (retained_operation != 48 && retained_operation != 49) ||
        (retained_operation == 49 && size != 1) ||
        !retained_output || size > 1024 || kmac_report[5] != 0) { return E_FAIL; }
    result = size == 0 ? S_OK : EnclaveCopyOutOfEnclave((void*)retained_output, source, size);
    if (result == S_OK) { kmac_report[5] = 1; }
    else { kmac_report[6] = 1; }
    return result;
}
int PublicKmacObserve(ULONG_PTR header, ULONG_PTR payload, ULONG_PTR clear) {
    if (!active || !retained_call) { return 0; }
    kmac_report[0]=header; kmac_report[1]=payload; kmac_report[2]=clear;
    return 1;
}
__declspec(dllexport) void* CALLBACK PublicKmacInputSource(void* context) {
    SIZE_T i;
    if (active || retained_call) { return 0; }
    kmac_source = (ULONG_PTR)context;
    for(i=0;i<7;++i) { kmac_report[i]=0; }
    return (void*)1;
}
__declspec(dllexport) void* CALLBACK PublicKmacControl(void* context) {
    ULONG_PTR word = (ULONG_PTR)context;
    if (active || retained_call || word < 16 || word >= 23) { return 0; }
    return (void*)kmac_report[word-16];
}
