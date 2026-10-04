/* Ordinary-process capture shim. Never a production enclave driver. */
#include <windows.h>
#include <string.h>
DWORD ProbeAvx;
unsigned char ProbePoison[32];
ULONG_PTR ProbeBefore[75], ProbeCount, ProbeHost[75], ProbeHostCount;
LPENCLAVE_ROUTINE ProbeTarget;
extern void* CALLBACK PublicTransitionHost(void*);
extern BOOL PrivateTransitionCall(LPENCLAVE_ROUTINE, void*, BOOL, void**);

/* Direct positive control uses normal process memory, not a VBS admission. */
BOOL PrivateTransitionAdmit(ULONG_PTR pointer, SIZE_T size) {
    return pointer != 0 && size == 312;
}
__declspec(dllexport) BOOL TransitionConfigure(LPENCLAVE_ROUTINE target, DWORD avx, DWORD seed) {
    if (!target || avx > 1 || (seed != 90 && seed != 165) ||
        (avx && !IsProcessorFeaturePresent(PF_AVX_INSTRUCTIONS_AVAILABLE))) return FALSE;
    ProbeAvx = avx;
    memset(ProbePoison, (int)seed, sizeof(ProbePoison));
    SecureZeroMemory(ProbeBefore, sizeof(ProbeBefore));
    SecureZeroMemory(ProbeHost, sizeof(ProbeHost));
    ProbeCount = ProbeHostCount = 0;
    ProbeTarget = target;
    return TRUE;
}
__declspec(dllexport) LPENCLAVE_ROUTINE TransitionAddress(void) { return PublicTransitionHost; }
__declspec(dllexport) ULONG_PTR TransitionQuery(ULONG_PTR index) {
    if (index == 0) return ProbeHostCount;
    if (index <= 75) return ProbeHost[index - 1];
    if (index == 76) return ProbeCount;
    if (index <= 151) return ProbeBefore[index - 77];
    return (ULONG_PTR)-1;
}
__declspec(dllexport) BOOL TransitionDirect(ULONG_PTR word) {
    void* result = NULL;
    return PrivateTransitionCall(PublicTransitionHost, (void*)word, FALSE, &result) && result == (void*)1;
}
