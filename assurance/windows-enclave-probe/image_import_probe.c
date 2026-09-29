/* Public-image OS enforcement control ONLY. No application enclave calls. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <intrin.h>
int wmain(int argc, wchar_t** argv) {
    ENCLAVE_CREATE_INFO_VBS create={0};
    ENCLAVE_INIT_INFO_VBS init={sizeof(ENCLAVE_INIT_INFO_VBS),1};
    void* base;
    BOOL loaded, initialized=FALSE;
    DWORD error, init_error=0;
    unsigned attempt;
    if (argc!=2) { return 99; }
    create.OwnerID[0]=0x42; create.OwnerID[1]=0x52;
    base=CreateEnclave(GetCurrentProcess(),NULL,0x10000000,0,ENCLAVE_TYPE_VBS,&create,sizeof(create),NULL);
    if (!base) { return 98; }
    loaded=LoadEnclaveImageW(base,argv[1]);
    error=loaded ? 0 : GetLastError();
    if (loaded) {
        initialized=InitializeEnclave(GetCurrentProcess(),base,&init,sizeof(init),NULL);
        init_error=initialized ? 0 : GetLastError();
    }
    if (initialized && !TerminateEnclave(base,FALSE)) { __fastfail(FAST_FAIL_FATAL_APP_EXIT); }
    for (attempt=0;attempt<100;++attempt) {
        if (DeleteEnclave(base)) { break; }
        if (GetLastError()!=ERROR_ENCLAVE_NOT_TERMINATED) { __fastfail(FAST_FAIL_FATAL_APP_EXIT); }
        Sleep(1);
    }
    if (attempt==100) { __fastfail(FAST_FAIL_FATAL_APP_EXIT); }
    printf("{\"loaded\":%u,\"error\":%lu,\"initialized\":%u,\"init_error\":%lu,\"deleted\":true}\n",
        loaded ? 1u:0u,error,initialized ? 1u:0u,init_error);
    return 0;
}
