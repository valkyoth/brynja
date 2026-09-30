/* Fixed synchronous ParallelHash transport. All cryptography remains first-party Rust. */
#include "window_retained.c"
static ULONG_PTR parallel_source, parallel_report[7];
ULONG_PTR PublicParallelSource(void) { return active && retained_call ? parallel_source : 0; }
int PublicParallelInput(ULONG_PTR kind, unsigned char* destination, ULONG_PTR source, SIZE_T size) {
    ULONG_PTR address = (ULONG_PTR)destination;
    int result;
    if (!active || !retained_call || kind > 1 || address < PublicLockedLow ||
        address > PublicLockedHigh || size > PublicLockedHigh-address || size > 1024 ||
        (kind == 0 && (size != 112 || parallel_report[3] != 0)) ||
        (kind == 1 && (size == 0 || parallel_report[3] != 1 || parallel_report[4] != 0))) { return E_FAIL; }
    result = EnclaveCopyIntoEnclave(destination, (const void*)source, size);
    if (result == S_OK) { parallel_report[3+kind] = 1; }
    else { parallel_report[6] = 1; }
    return result;
}
int PublicParallelOutput(const unsigned char* source, SIZE_T size) {
    int result;
    if (!active || !retained_call || !retained_live || retained_operation != 106 ||
        !retained_output || size > 1024 || parallel_report[5] != 0) { return E_FAIL; }
    result = size == 0 ? S_OK : EnclaveCopyOutOfEnclave((void*)retained_output, source, size);
    if (result == S_OK) { parallel_report[5] = 1; }
    else { parallel_report[6] = 1; }
    return result;
}
int PublicParallelObserve(ULONG_PTR header, ULONG_PTR payload, ULONG_PTR clear) {
    if (!active || !retained_call) { return 0; }
    parallel_report[0]=header; parallel_report[1]=payload; parallel_report[2]=clear;
    return 1;
}
__declspec(dllexport) void* CALLBACK PublicParallelInputSource(void* context) {
    SIZE_T i;
    if (active || retained_call) { return 0; }
    parallel_source = (ULONG_PTR)context;
    for(i=0;i<7;++i) { parallel_report[i]=0; }
    return (void*)1;
}
__declspec(dllexport) void* CALLBACK PublicParallelControl(void* context) {
    ULONG_PTR word = (ULONG_PTR)context;
    if (active || retained_call || word < 16 || word >= 23) { return 0; }
    return (void*)parallel_report[word-16];
}
