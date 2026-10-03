/* Private public-output ingress experiment; same three-wave native scheduler.
 * Config contains public host addresses only. Rust never dereferences them.
 * All payload transfers use the enclave OS copy primitives. */
static volatile LONG input_registration, input_exported;
static PVOID input_output;
static volatile LONG input_copies[3], input_errors;

__declspec(dllexport) void* CALLBACK PublicInputOutputSource(void* context) {
    if (context == NULL || InterlockedCompareExchange(&root_claimed, 0, 0) != 0 ||
        InterlockedCompareExchange(&input_registration, 1, 0) != 0) return 0;
    input_output = context;
    InterlockedExchange(&input_registration, 2);
    return (void*)1;
}

ULONG_PTR PrivateInputCopy(ULONG_PTR kind, ULONG_PTR source, unsigned char* destination, SIZE_T size) {
    HRESULT result;
    if (kind > 2 || source == 0 || source > (ULONG_PTR)-1 - size ||
        !PrivateWaveRootRegion((ULONG_PTR)destination, size) ||
        (kind == 0 && (size != 128 || input_copies[0] != 0)) ||
        (kind == 1 && (size == 0 || size > 1024 || input_copies[0] != 1 || input_copies[1] != 0)) ||
        (kind == 2 && (size == 0 || size > 4096 || input_copies[0] != 1 || input_copies[2] >= 3))) return 0;
    result = EnclaveCopyIntoEnclave(destination, (const void*)source, size);
    if (result != S_OK) { InterlockedIncrement(&input_errors); return 0; }
    InterlockedIncrement(&input_copies[kind]);
    return 1;
}

ULONG_PTR PrivateInputOutput(const unsigned char* source, SIZE_T size) {
    HRESULT result;
    if (InterlockedCompareExchange(&input_registration, 0, 0) != 2 || size > 1024 ||
        input_copies[2] != 3 || !PrivateWaveRootRegion((ULONG_PTR)source, size) ||
        InterlockedCompareExchange(&input_exported, 1, 0) != 0) return 0;
    result = size == 0 ? S_OK : EnclaveCopyOutOfEnclave(input_output, source, size);
    if (result != S_OK) { InterlockedIncrement(&input_errors); return 0; }
    InterlockedExchange(&input_exported, 2);
    return 1;
}

/* Only public transfer counts, and only after the root frame has completed. */
__declspec(dllexport) void* CALLBACK PublicInputQuery(void* context) {
    ULONG_PTR field = (ULONG_PTR)context;
    if (InterlockedCompareExchange(&slots[12].done, 0, 0) != 1) return (void*)(ULONG_PTR)-1;
    if (field < 3) return (void*)(ULONG_PTR)InterlockedCompareExchange(&input_copies[field], 0, 0);
    if (field == 3) return (void*)(ULONG_PTR)InterlockedCompareExchange(&input_exported, 0, 0);
    if (field == 4) return (void*)(ULONG_PTR)InterlockedCompareExchange(&input_errors, 0, 0);
    return (void*)(ULONG_PTR)-1;
}
