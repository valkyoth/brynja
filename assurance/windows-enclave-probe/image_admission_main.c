/* Development admission integration. No confidential input or public API yet. */
#include "image_pin.h"
#include <wintrust.h>
#include <softpub.h>
#include <stdio.h>
#include <intrin.h>
#if defined(BRYNJA_ADMISSION_PRODUCTION) == defined(BRYNJA_ADMISSION_DEVELOPMENT)
#error Select exactly one deployment profile at build time
#endif

static LONG signature(const wchar_t* path, HANDLE file) {
    WINTRUST_FILE_INFO info = {0};
    WINTRUST_DATA trust = {0};
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG result, closed;
    info.cbStruct = sizeof(info); info.pcwszFilePath = path; info.hFile = file;
    trust.cbStruct = sizeof(trust); trust.dwUIChoice = WTD_UI_NONE;
    trust.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trust.dwUnionChoice = WTD_CHOICE_FILE; trust.pFile = &info;
    trust.dwStateAction = WTD_STATEACTION_VERIFY;
    trust.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_DISABLE_MD2_MD4;
    result = WinVerifyTrust(INVALID_HANDLE_VALUE, &action, &trust);
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    closed = WinVerifyTrust(INVALID_HANDLE_VALUE, &action, &trust);
    return result == ERROR_SUCCESS ? closed : result;
}

int wmain(int argc, wchar_t** argv) {
    PINNED_IMAGE pin;
    ENCLAVE_CREATE_INFO_VBS create = {0};
    ENCLAVE_INIT_INFO_VBS init = {sizeof(ENCLAVE_INIT_INFO_VBS), 1};
    void* base = NULL;
    void* value = NULL;
    LPENCLAVE_ROUTINE routine;
    LONG trust = TRUST_E_NOSIGNATURE;
    DWORD error = 0;
    unsigned stage = 1, initialized = 0, loaded = 0, called = 0, attempt;
    int pinned = 0;
    if (argc != 2) { return 99; }
    if (!ImagePinOpen(&pin,argv[1])) { goto done; }
    pinned = 1; stage = 2;
    /* Check in development too, but never turn the result into production trust. */
    trust = signature(argv[1],pin.file);
#ifdef BRYNJA_ADMISSION_PRODUCTION
    if (trust != ERROR_SUCCESS) { goto done; }
#endif
    stage = 3;
    create.OwnerID[0]=0x42; create.OwnerID[1]=0x52;
    base=CreateEnclave(GetCurrentProcess(),NULL,0x10000000,0,ENCLAVE_TYPE_VBS,&create,sizeof(create),NULL);
    if (!base) { error=GetLastError(); goto done; }
    stage = 4;
    /* Windows verifies the enclave signature and the inspected enclave import identities. */
    if (!LoadEnclaveImageW(base,argv[1])) { error=GetLastError(); goto done; }
    loaded = 1; stage = 5;
    if (!InitializeEnclave(GetCurrentProcess(),base,&init,sizeof(init),NULL)) { error=GetLastError(); goto done; }
    initialized = 1;
    if (init.ThreadCount != 1) { goto done; }
    stage = 6;
    routine=(LPENCLAVE_ROUTINE)GetProcAddress((HMODULE)base,"PublicProbe");
    if (!routine || !CallEnclave(routine,(void*)0x1234,FALSE,&value)
        || (ULONG_PTR)value != (0x1234 ^ 0x4252594e)) { error=GetLastError(); goto done; }
    called=1; stage=0;
done:
    if (base) {
        if (initialized && !TerminateEnclave(base,FALSE)) { __fastfail(FAST_FAIL_FATAL_APP_EXIT); }
        for (attempt=0;attempt<100;++attempt) {
            if (DeleteEnclave(base)) { break; }
            if (GetLastError()!=ERROR_ENCLAVE_NOT_TERMINATED) { __fastfail(FAST_FAIL_FATAL_APP_EXIT); }
            Sleep(1);
        }
        if (attempt==100) { __fastfail(FAST_FAIL_FATAL_APP_EXIT); }
    }
    /* Keep all file/ancestor handles until confirmed image destruction. */
    if (pinned && !ImagePinClose(&pin)) { __fastfail(FAST_FAIL_FATAL_APP_EXIT); }
#ifdef BRYNJA_ADMISSION_PRODUCTION
    printf("{\"profile\":\"production\",");
#else
    printf("{\"profile\":\"development\",");
#endif
    printf("\"stage\":%u,\"trust_status\":%ld,\"os_error\":%lu,\"loaded\":%u,\"called\":%u,\"cleanup\":true}\n",
        stage,trust,error,loaded,called);
    return stage ? 97 : 0;
}
