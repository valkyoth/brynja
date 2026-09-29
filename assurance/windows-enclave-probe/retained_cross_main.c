/* Public-vector routing diagnostic. Tokens are public metadata, not capabilities. */
#include "native_host.h"
#include <stdio.h>
#include <string.h>
int RetainedInputRun(void*, uint64_t, const unsigned char*, unsigned char*, uint64_t*);
/* ORACLE */
static int run(HOST_INSTANCE* owner, uint64_t op, const unsigned char* input,
               unsigned char* output, uint64_t status) {
    uint64_t report[4] = {0};
    return RetainedInputRun(owner,op,input,output,report) && report[0] == status;
}
static int begin(HOST_INSTANCE* owner, const char* message) {
    uint64_t header[4] = {4,0,3,0};
    if(!run(owner,0,NULL,NULL,1)) { return 0; }
    header[1]=owner->input_epoch; header[3]=(uint64_t)(uintptr_t)message;
    return run(owner,1,(const unsigned char*)header,NULL,2);
}
static int token(HOST_INSTANCE* owner, uint64_t result[4]) {
    LPENCLAVE_ROUTINE control=(LPENCLAVE_ROUTINE)GetProcAddress((HMODULE)owner->base,"PublicCrossControl");
    unsigned i;
    for(i=0;i<4;++i) { if(!HostCall(control,16+i,&result[i])) { return 0; } }
    return result[0]>=(uint64_t)(uintptr_t)owner->base &&
        result[0]-(uint64_t)(uintptr_t)owner->base<0x10000000 &&
        result[1]==owner->input_epoch && result[2]==1 && result[3]==1;
}
static int cross(HOST_INSTANCE* owner, const uint64_t supplied[4], uint64_t expected) {
    memcpy(owner->cross_token,supplied,32); owner->cross_expected=expected;
    return run(owner,10,(const unsigned char*)supplied,NULL,expected);
}
static int rejected_cleanup(HOST_INSTANCE* owner) {
    unsigned char output[32]; unsigned i;
    memset(output,0xcc,32); owner->cross_quarantine=TRUE;
    if(!run(owner,2,NULL,output,107)) { return 0; }
    owner->cross_quarantine=FALSE;
    for(i=0;i<32;++i) { if(output[i]!=0xcc) { return 0; } }
    return run(owner,3,NULL,NULL,4);
}
static int campaign(const wchar_t* image) {
    HOST_INSTANCE* owners[2];
    const char* messages[2] = {"abc","xyz"};
    uint64_t tokens[2][4], original[4], stale[4], changed[4];
    unsigned round,field; unsigned char output[32];
    owners[0]=HostOpen(image); owners[1]=HostOpen(image);
    if(!owners[0] || !owners[1]) { return 10; }
    for(round=0;round<2;++round) {
        HOST_INSTANCE* origin=owners[round]; HOST_INSTANCE* victim=owners[1-round];
        if(!begin(owners[0],messages[0]) || !begin(owners[1],messages[1])) { return 11; }
        if(!token(owners[0],tokens[0]) || !token(owners[1],tokens[1]) ||
            tokens[0][0]==tokens[1][0] || tokens[0][1]!=tokens[1][1] || tokens[0][2]!=tokens[1][2]) { return 13; }
        memcpy(stale,tokens[0],32); memcpy(original,tokens[round],32);
        if(!cross(victim,original,103)) { return 21; }
        if(!rejected_cleanup(victim)) { return 22; }
        if(!token(origin,changed) || memcmp(original,changed,32)) { return 23; }
        if(!cross(origin,original,8)) { return 24; }
        memset(output,0xcc,32);
        if(!run(origin,2,NULL,output,3) || memcmp(output,expected[round],32) ||
            !run(origin,3,NULL,NULL,4)) { return 25; }
    }
    /* Same live enclave, recreated owner: epoch prevents address/owner reuse. */
    if(!begin(owners[0],messages[0]) || !cross(owners[0],stale,103) ||
        !rejected_cleanup(owners[0])) { return 30; }
    for(field=0;field<4;++field) {
        if(!begin(owners[0],messages[0]) || !token(owners[0],changed)) { return 31; }
        changed[field]^=1;
        if(!cross(owners[0],changed,103) || !rejected_cleanup(owners[0])) { return 32; }
    }
    if(!HostClose(owners[0]) || !HostClose(owners[1])) { return 40; }
    return 0;
}
int wmain(int argc,wchar_t** argv) {
    int result=argc==2?campaign(argv[1]):99;
    printf("{\"result\":%d,\"created\":%llu,\"deleted\":%llu,\"calls\":%llu,"
           "\"retained\":%llu,\"cleanup_errors\":%llu}\n",result,
           HostCounter(0),HostCounter(1),HostCounter(2),HostCounter(3),HostCounter(4));
    return result==0 && HostCounter(0)==2 && HostCounter(1)==2 && HostCounter(2)==45 &&
        HostCounter(3)==0 && HostCounter(4)==0 ? 0 : 97;
}
