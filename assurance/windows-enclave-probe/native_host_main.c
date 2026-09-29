#include "native_host.h"
#include <stdio.h>
#include <wchar.h>
extern uint32_t HostCampaign(const wchar_t* image, size_t length);

int wmain(int argc, wchar_t** argv) {
    uint32_t result;
    if (argc != 2) { return 99; }
    result = HostCampaign(argv[1], wcslen(argv[1]) + 1);
    printf("{\"result\":%u,\"created\":%llu,\"deleted\":%llu,\"calls\":%llu,"
           "\"retained\":%llu,\"cleanup_errors\":%llu}\n", result, HostCounter(0), HostCounter(1),
           HostCounter(2), HostCounter(3), HostCounter(4));
#if defined(BRYNJA_HOST_FAIL_DELETE)
    return result == 14 && HostCounter(0) == 1 && HostCounter(1) == 0
        && HostCounter(2) == 60 && HostCounter(3) == 1 && HostCounter(4) == 2 ? 0 : 96;
#elif defined(BRYNJA_HOST_FAIL_CREATE) || defined(BRYNJA_HOST_FAIL_LOAD) || defined(BRYNJA_HOST_FAIL_INIT)
    return result == 10 && HostCounter(0) == 1 && HostCounter(1) == 1
        && HostCounter(2) == 0 && HostCounter(3) == 0 && HostCounter(4) == 0 ? 0 : 98;
#else
    return result == 0 && HostCounter(0) == 5 && HostCounter(1) == 5
        && HostCounter(2) == 63 && HostCounter(3) == 0 && HostCounter(4) == 0 ? 0 : 97;
#endif
}
