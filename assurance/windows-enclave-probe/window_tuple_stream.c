/* Fixed synchronous TupleHash transport. All cryptography remains first-party Rust. */
#include "window_retained.c"
static ULONG_PTR tuple_source, tuple_report[7];
ULONG_PTR PublicTupleSource(void) { return active && retained_call ? tuple_source : 0; }
int PublicTupleInput(ULONG_PTR kind, unsigned char* destination, ULONG_PTR source, SIZE_T size) {
    ULONG_PTR address = (ULONG_PTR)destination;
    int result;
    if (!active || !retained_call || kind > 1 || address < PublicLockedLow ||
        address > PublicLockedHigh || size > PublicLockedHigh-address || size > 1024 ||
        (kind == 0 && (size != 96 || tuple_report[3] != 0)) ||
        (kind == 1 && (size == 0 || tuple_report[3] != 1 || tuple_report[4] != 0))) { return E_FAIL; }
    result = EnclaveCopyIntoEnclave(destination, (const void*)source, size);
    if (result == S_OK) { tuple_report[3+kind] = 1; }
    else { tuple_report[6] = 1; }
    return result;
}
int PublicTupleOutput(const unsigned char* source, SIZE_T size) {
    int result;
    if (!active || !retained_call || !retained_live || retained_operation != 68 ||
        !retained_output || size > 1024 || tuple_report[5] != 0) { return E_FAIL; }
    result = size == 0 ? S_OK : EnclaveCopyOutOfEnclave((void*)retained_output, source, size);
    if (result == S_OK) { tuple_report[5] = 1; }
    else { tuple_report[6] = 1; }
    return result;
}
int PublicTupleObserve(ULONG_PTR header, ULONG_PTR payload, ULONG_PTR clear) {
    if (!active || !retained_call) { return 0; }
    tuple_report[0]=header; tuple_report[1]=payload; tuple_report[2]=clear;
    return 1;
}
__declspec(dllexport) void* CALLBACK PublicTupleInputSource(void* context) {
    SIZE_T i;
    if (active || retained_call) { return 0; }
    tuple_source = (ULONG_PTR)context;
    for(i=0;i<7;++i) { tuple_report[i]=0; }
    return (void*)1;
}
__declspec(dllexport) void* CALLBACK PublicTupleControl(void* context) {
    ULONG_PTR word = (ULONG_PTR)context;
    if (active || retained_call || word < 16 || word >= 23) { return 0; }
    return (void*)tuple_report[word-16];
}
