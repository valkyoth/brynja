"""Bind normal DLL process-attach ordering, not loader or exception attestation."""
from windows_enclave_runtime_startup_bytes import BODIES
from hashlib import sha256
import windows_enclave_sdk_return as sdk

require=sdk.require


def executable(rows,address,size):
    owners=[r for r in rows if r['rva']<=address and
        address+size<=r['rva']+min(r['virtual_size'],len(r['code']))]
    require(len(owners)==1 and owners[0]['flags']&0xe0000000==0x60000000,
        'entire startup body in nonwritable executable storage')
    return sdk.mapped(rows,address,size)


def normalize(name,code,address):
    _,hex_code,refs=BODIES[name];expected=bytes.fromhex(hex_code)
    require(len(code)==len(expected),'complete startup runtime function')
    result=bytearray(code);targets={};identities={}
    for offset,end,role in refs:
        target=address+end+int.from_bytes(code[offset:offset+4],'little',signed=True)
        require(role not in identities or identities[role]==target,'repeated startup identity')
        require(0<target<1<<32,'bounded startup reference')
        identities[role]=target;targets[offset]=target;result[offset:offset+4]=bytes(4)
    require(result==expected,'whole startup body including every branch and return')
    return targets


def inspect(image,initializer):
    rows,functions=sdk.pe.linked(image);found={}
    for name,(_,hex_code,refs) in BODIES.items():
        expected=bytes.fromhex(hex_code);matches=[]
        for a,b,u in functions:
            if b-a!=len(expected):continue
            code=executable(rows,a,b-a)
            try:targets=normalize(name,code,a)
            except ValueError:continue
            matches.append(dict(rva=a,bytes=b-a,sha256=sha256(code).hexdigest(),targets=targets))
        require(len(matches)==1,'one complete startup '+name);found[name]=matches[0]
    pe_offset,=sdk.pe.unpack('<I',image,0x3c)
    entry,=sdk.pe.unpack('<I',image,pe_offset+24+16)
    require(entry==found['entry']['rva'],'actual PE entry point, not detached matching code')
    for caller,offset,callee in (('entry',57,'main'),('main',107,'dispatch'),
            ('main',221,'dispatch'),('dispatch',61,'attach'),('attach',30,'crt')):
        require(found[caller]['targets'][offset]==found[callee]['rva'],'actual startup call chain')
    require(found['crt']['targets'][16]==initializer,'unconditional call to actual selector initializer')
    require(found['main']['targets'][40]==found['attach']['targets'][231],
        'same process-attach counter in dispatch and startup')
    # The optional pre-CRT callback is NULL in these exact signed images. Do
    # not extrapolate this ordering to arbitrary user-injected startup hooks.
    raw=found['main']['targets'][64]
    owners=[r for r in rows if r['rva']<=raw and raw+8<=r['rva']+r['virtual_size']]
    require(len(owners)==1 and owners[0]['flags']&0xe0000000==0x40000000,
        'pre-CRT hook in readonly nonexecutable storage')
    require(sdk.mapped(rows,raw,8)==bytes(8),'no arbitrary pre-CRT hook')
    dllmain=found['main']['targets'][134]
    require(found['main']['targets'][162]==dllmain,'same application DllMain on detach')
    require(executable(rows,dllmain,6)==bytes.fromhex('b801000000c3'),
        'application DllMain is the reviewed constant-success leaf')
    return dict(bodies=found,pre_crt_hook_rva=raw,application_dllmain_rva=dllmain,
        normal_process_attach_initializes_selectors_before_application=True,
        required_loader_contract='loader calls PE entry successfully before exposing application exports',
        loaded_startup_order_observed=False,arbitrary_runtime_callbacks_qualified=False,
        exception_paths_qualified=False)
