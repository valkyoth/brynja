/* Private version-21 eight-lane worker transport. Development fixture only. */
#include <winenclave.h>
#include "cpu_inventory.c"
#include "sha256_simd_gate.h"
#include "window_retained.c"
static ULONG_PTR simd_source, simd_report[7];
ULONG_PTR PublicSha256SimdSource(void) { return active && retained_call ? simd_source : 0; }
int PublicSha256SimdInput(ULONG_PTR kind, unsigned char* destination, ULONG_PTR source, SIZE_T size) {
    ULONG_PTR address = (ULONG_PTR)destination;
    int result;
    if (!active || !retained_call || kind > 8 || address < PublicLockedLow ||
        address > PublicLockedHigh || size > PublicLockedHigh-address || size > 1024 ||
        (kind == 0 && (size != 288 || simd_report[3] != 0)) ||
        (kind != 0 && (retained_operation != 100 || size < 64 || simd_report[3] != 1 ||
                       simd_report[4] != kind-1)) || simd_report[6]) { return E_FAIL; }
    result = EnclaveCopyIntoEnclave(destination, (const void*)source, size);
    if (result == S_OK) {
        if (kind == 0) { simd_report[3] = 1; } else { simd_report[4] = kind; }
    } else { simd_report[6] = 1; }
    return result;
}
int PublicSha256SimdOutput(const unsigned char* source, SIZE_T size) {
    int result;
    if (!active || !retained_call || !retained_live || retained_operation != 101 ||
        !retained_output || size != 256 || simd_report[3] != 1 || simd_report[4] != 0 ||
        simd_report[5] != 0 || simd_report[6]) { return E_FAIL; }
    result = EnclaveCopyOutOfEnclave((void*)retained_output, source, size);
    if (result == S_OK) { simd_report[5] = 1; } else { simd_report[6] = 1; }
    return result;
}
int PublicSha256SimdObserve(ULONG_PTR header, ULONG_PTR payload, ULONG_PTR clear) {
    if (!active || !retained_call) { return 0; }
    simd_report[0]=header; simd_report[1]=payload; simd_report[2]=clear;
    return 1;
}
__declspec(dllexport) void* CALLBACK PublicSha256SimdInputSource(void* context) {
    SIZE_T i;
    if (active || retained_call) { return 0; }
    simd_source=(ULONG_PTR)context;
    for (i=0;i<7;++i) { simd_report[i]=0; }
    return (void*)1;
}
__declspec(dllexport) void* CALLBACK PublicSha256SimdControl(void* context) {
    ULONG_PTR word=(ULONG_PTR)context;
    if (active || retained_call || word < 16 || word >= 23) { return 0; }
    return (void*)simd_report[word-16];
}
__declspec(dllexport) void* CALLBACK PublicSha256SimdProtocol(void* context) {
    if (context || active || retained_call || !Sha256SimdReady()) { return 0; }
    return (void*)(ULONG_PTR)0x42524234;
}
