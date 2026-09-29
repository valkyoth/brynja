/* Isolated fatal checkpoint. Public vectors only; never linked into normal host. */
#include "native_host.h"
#include <stdio.h>
#include <string.h>
#include <wchar.h>

extern uint32_t HostCampaign(const wchar_t* image, size_t length);
static unsigned char* control;
static ULONG_PTR selected;

void HostDumpCheckpoint(void* base, ULONG_PTR low, ULONG_PTR event,
                        const unsigned char* command, const unsigned char* output) {
    uint64_t offer[8];
    if (event != selected) { return; }
    memcpy(offer, command, sizeof(offer));
    if (!control || (offer[0] | offer[1]) == 0 || offer[2] != 1 || offer[3] != 1
        || offer[4] != (event == 2 ? 0 : 1) || offer[5] || offer[6] || offer[7]) {
        ExitProcess(91);
    }
    /* Called only after all 16 pages were rechecked locked in the fixed callback.
     * Flush metadata before fail-fast; no secret or arbitrary memory is logged. */
    printf("{\"pid\":%lu,\"base\":%llu,\"window\":%llu,\"control\":%llu,"
           "\"staging\":%llu,\"event\":%llu,\"locked_pages\":16,\"epoch\":1}\n",
           GetCurrentProcessId(), (uint64_t)(ULONG_PTR)base, (uint64_t)low,
           (uint64_t)(ULONG_PTR)control, (uint64_t)(ULONG_PTR)output, (uint64_t)event);
    if (fflush(stdout) != 0) { ExitProcess(92); }
    RaiseFailFastException(NULL, NULL, 0);
    ExitProcess(93); /* Must not return; no cleanup claim on this fatal path. */
}

int wmain(int argc, wchar_t** argv) {
    uint32_t result;
    if (argc != 3 || (wcscmp(argv[2], L"2") != 0 && wcscmp(argv[2], L"3") != 0)) { return 94; }
    selected = wcscmp(argv[2], L"2") == 0 ? 2 : 3;
    control = (unsigned char*)VirtualAlloc(NULL, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!control) { return 95; }
    memset(control, 0x5a, 8192);
    result = HostCampaign(argv[1], wcslen(argv[1]) + 1);
    memset(control, 0, 8192);
    if (!VirtualFree(control, 0, MEM_RELEASE)) { return 96; }
    return result == 0 ? 97 : 98; /* Normal completion is NOT a crash observation. */
}
