/* New research image, no changes to the existing retained signed fixture. */
#include "window_retained.c"
static ULONG_PTR input_source, input_report[11];

ULONG_PTR PublicInputSource(void) {
    return active && retained_call ? input_source : 0;
}
int PublicInputCopy(ULONG_PTR kind, unsigned char* destination, ULONG_PTR source, SIZE_T size) {
    int result;
    ULONG_PTR address = (ULONG_PTR)destination;
    if (!active || !retained_call || kind > 1 || address < PublicLockedLow ||
        size > 1024 || address > PublicLockedHigh || size > PublicLockedHigh - address ||
        (kind == 0 && size != 32) || (kind == 1 && (size == 0 || input_report[1] != 1))) { return E_FAIL; }
    input_report[kind * 2] += 1; /* Bounded fixed worker calls, never an untrusted loop. */
    result = EnclaveCopyIntoEnclave(destination, (const void*)source, size);
    if (result == S_OK) { input_report[kind * 2 + 1] += 1; }
    return result;
}
int PublicInputObserve(const ULONG_PTR* values) {
    SIZE_T i;
    ULONG_PTR address = (ULONG_PTR)values;
    if (!active || !retained_call || address < PublicLockedLow || address > PublicLockedHigh ||
        7 * sizeof(ULONG_PTR) > PublicLockedHigh - address) { return 0; }
    for (i = 0; i < 7; ++i) { input_report[i + 4] = values[i]; }
    return 1;
}
__declspec(dllexport) void* CALLBACK PublicRetainedInput(void* context) {
    SIZE_T i;
    if (active || retained_call) { return 0; }
    input_source = (ULONG_PTR)context;
    for (i = 0; i < 11; ++i) { input_report[i] = 0; }
    return (void*)1;
}
__declspec(dllexport) void* CALLBACK PublicInputControl(void* context) {
    ULONG_PTR op = (ULONG_PTR)context;
    if (active || retained_call || op < 16 || op >= 27) { return 0; }
    return (void*)input_report[op - 16];
}
