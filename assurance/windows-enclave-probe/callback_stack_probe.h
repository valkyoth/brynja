/* Instrumented-image diagnostic ONLY. Stores public stack addresses/counts,
 * never payload or register contents. Root events are serial on lane four. */
#include <intrin.h>
extern ULONG_PTR PrivateCallbackStack(void);
static ULONG_PTR callback_frames[3][7];

static void observe_callback(STACK_SLOT* slot, ULONG_PTR event, ULONG_PTR frame,
                             ULONG_PTR reply, ULONG_PTR stack, BOOL after) {
    ULONG_PTR* row;
    ULONG_PTR starts[3] = {frame, reply, stack};
    ULONG_PTR sizes[3] = {8, 8, 40}; /* helper return address + caller shadow */
    unsigned index;
    if (event < 2 || event > 4) return;
    row = callback_frames[event - 2];
    row[after ? 1 : 0]++;
    if (slot != &slots[4] || !slot->admitted || slot->cleared) row[6]++;
    for (index = 0; index < 3; ++index) {
        if (starts[index] < slot->low || starts[index] > slot->high ||
            sizes[index] > slot->high - starts[index]) row[6]++;
        if (row[2] == 0 || starts[index] < row[2]) row[2] = starts[index];
        if (starts[index] <= (ULONG_PTR)-1 - sizes[index] &&
            starts[index] + sizes[index] > row[3]) row[3] = starts[index] + sizes[index];
    }
    if (row[4] == 0 || stack < row[4]) row[4] = stack;
    if (stack > row[5]) row[5] = stack;
}

__declspec(noinline) static BOOL notify(STACK_SLOT* slot, ULONG_PTR event) {
    void* reply = NULL;
    BOOL ok;
    ULONG_PTR stack = PrivateCallbackStack();
    observe_callback(slot, event, (ULONG_PTR)_AddressOfReturnAddress(),
                     (ULONG_PTR)&reply, stack, FALSE);
    ok = stack_callback != NULL &&
        CallEnclave(stack_callback, (void*)(slot->low | (slot->lane << 4) | event),
                    FALSE, &reply) && reply == (void*)1;
    stack = PrivateCallbackStack();
    observe_callback(slot, event, (ULONG_PTR)_AddressOfReturnAddress(),
                     (ULONG_PTR)&reply, stack, TRUE);
    return ok;
}

/* Call only after the root returns. No early view of partially written rows. */
__declspec(dllexport) void* CALLBACK PublicCallbackFrameQuery(void* context) {
    ULONG_PTR word = (ULONG_PTR)context;
    if (word >= 21 || InterlockedCompareExchange(&slots[4].done, 0, 0) != 1)
        return (void*)(ULONG_PTR)-1;
    return (void*)callback_frames[word / 7][word % 7];
}
