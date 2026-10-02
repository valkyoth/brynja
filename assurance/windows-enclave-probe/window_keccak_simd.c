/* Private version-22 four-message worker transport. Development fixture only. */
#include <winenclave.h>
#include "cpu_inventory.c"
#include "keccak_simd_gate.h"
#include "window_retained.c"
static ULONG_PTR simd_source, simd_report[7], simd_last_kind;
ULONG_PTR PublicKeccakSimdSource(void) { return active && retained_call ? simd_source : 0; }
int PublicKeccakSimdInput(ULONG_PTR kind, unsigned char* destination, ULONG_PTR source, SIZE_T size) {
    ULONG_PTR address = (ULONG_PTR)destination;
    int result;
    if (!active || !retained_call || kind > 12 || !source || address < PublicLockedLow ||
        address > PublicLockedHigh || size > PublicLockedHigh-address || size > 1024 ||
        (kind == 0 && (size != 384 || simd_report[3] != 0)) ||
        (kind != 0 && (retained_operation != 100 || size == 0 || simd_report[3] != 1 ||
                       kind <= simd_last_kind)) || simd_report[6]) { return E_FAIL; }
    result = EnclaveCopyIntoEnclave(destination, (const void*)source, size);
    if (result == S_OK) {
        if (kind == 0) { simd_report[3] = 1; }
        else { ++simd_report[4]; simd_last_kind = kind; }
    } else { simd_report[6] = 1; }
    return result;
}
int PublicKeccakSimdOutput(const unsigned char* source, SIZE_T size) {
    int result;
    if (!active || !retained_call || !retained_live || retained_operation != 101 ||
        !retained_output || size != 1024 || simd_report[3] != 1 || simd_report[4] != 0 ||
        simd_report[5] != 0 || simd_report[6]) { return E_FAIL; }
    result = EnclaveCopyOutOfEnclave((void*)retained_output, source, size);
    if (result == S_OK) { simd_report[5] = 1; } else { simd_report[6] = 1; }
    return result;
}
int PublicKeccakSimdObserve(ULONG_PTR header, ULONG_PTR payload, ULONG_PTR clear) {
    if (!active || !retained_call) { return 0; }
    simd_report[0]=header; simd_report[1]=payload; simd_report[2]=clear;
    return 1;
}
__declspec(dllexport) void* CALLBACK PublicKeccakSimdInputSource(void* context) {
    SIZE_T i;
    if (active || retained_call) { return 0; }
    simd_source=(ULONG_PTR)context;
    simd_last_kind=0;
    for (i=0;i<7;++i) { simd_report[i]=0; }
    return (void*)1;
}
__declspec(dllexport) void* CALLBACK PublicKeccakSimdControl(void* context) {
    ULONG_PTR word=(ULONG_PTR)context;
    if (active || retained_call || word < 16 || word >= 23) { return 0; }
    return (void*)simd_report[word-16];
}
__declspec(dllexport) void* CALLBACK PublicKeccakSimdProtocol(void* context) {
    if (context || active || retained_call || !KeccakSimdReady()) { return 0; }
    return (void*)(ULONG_PTR)0x42524235;
}
