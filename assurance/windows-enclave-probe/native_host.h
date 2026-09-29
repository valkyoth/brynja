/* Public-data research host only. Not a shipped Windows backend. */
#ifndef BRYNJA_NATIVE_HOST_H
#define BRYNJA_NATIVE_HOST_H
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <enclaveapi.h>
#include <stdint.h>
#include <stddef.h>

typedef int (*HOST_PROTOCOL)(void*, uint64_t, unsigned char*, const unsigned char*);
typedef struct { uint64_t first, second, inner_clear, outer_clear; } HOST_REPORT;
_Static_assert(sizeof(HOST_REPORT) == 32, "host report ABI");
typedef struct HOST_INSTANCE {
    void* base;
    BOOL initialized, termination_requested, busy;
    DWORD owner_thread;
    LPENCLAVE_ROUTINE wire, window, registration, control, guard;
} HOST_INSTANCE;

void* HostOpen(const wchar_t* image);
int HostClose(void* opaque);
int HostRun(void* opaque, void* user, HOST_PROTOCOL protocol, const unsigned char* request,
            unsigned char* command, unsigned char* output, uint64_t fault, HOST_REPORT* report);
uint64_t HostCounter(uint64_t which);
BOOL HostCall(LPENCLAVE_ROUTINE routine, ULONG_PTR parameter, ULONG_PTR* result);
void HostCountRun(void);
__declspec(noreturn) void HostAbort(void);
#endif
