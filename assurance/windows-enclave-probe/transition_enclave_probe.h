/* Diagnostic only, configured before execution. Public patterns only. */
DWORD ProbeAvx;
unsigned char ProbePoison[32];
ULONG_PTR ProbeBefore[75], ProbeCount;
static BOOL transition_configured;
extern BOOL PrivateTransitionCall(LPENCLAVE_ROUTINE, void*, BOOL, void**);

BOOL PrivateTransitionAdmit(ULONG_PTR pointer, SIZE_T size) {
    STACK_SLOT* root = &slots[4];
    return transition_configured && root->admitted && !root->cleared &&
        pointer >= root->low && pointer <= root->high && size <= root->high - pointer;
}

__declspec(dllexport) void* CALLBACK PublicTransitionConfigure(void* context) {
    ULONG_PTR word = (ULONG_PTR)context, seed = word & 255;
    unsigned index;
    if (transition_configured || word > 511 || (seed != 90 && seed != 165) ||
        InterlockedCompareExchange(&root_claimed, 0, 0) != 0) return 0;
    ProbeAvx = (DWORD)(word >> 8);
    for (index = 0; index < sizeof(ProbePoison); ++index) ProbePoison[index] = (unsigned char)seed;
    transition_configured = TRUE;
    return (void*)1;
}

static BOOL notify(STACK_SLOT* slot, ULONG_PTR event) {
    void* reply = NULL;
    if (stack_callback == NULL) return FALSE;
    if (event >= 2 && event <= 4) {
        if (slot != &slots[4] || !slot->admitted || slot->cleared) return FALSE;
        return PrivateTransitionCall(stack_callback, (void*)(slot->low | (slot->lane << 4) | event),
                                     FALSE, &reply) && reply == (void*)1;
    }
    return CallEnclave(stack_callback, (void*)(slot->low | (slot->lane << 4) | event),
                       FALSE, &reply) && reply == (void*)1;
}

__declspec(dllexport) void* CALLBACK PublicTransitionQuery(void* context) {
    ULONG_PTR word = (ULONG_PTR)context;
    if (word > 75 || InterlockedCompareExchange(&slots[4].done, 0, 0) != 1)
        return (void*)(ULONG_PTR)-1;
    return (void*)(word == 0 ? ProbeCount : ProbeBefore[word - 1]);
}
