"""All nineteen saved images: memory dispatch/initializer and import identities.

Offline author review. Does not attest loaded imports, establish stack depth,
qualify exceptions, or execute an enclave. No release-gate integration.
"""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_route_memory as memory
import windows_enclave_parallel_inventory as parallel
import windows_enclave_runtime_startup as startup
from windows_enclave_runtime_init_bytes import INIT_CODE,INIT_REFS

shared=memory.shared
sdk=shared.sdk
require,digest=shared.require,shared.digest
INIT=bytes.fromhex(INIT_CODE)
ROUTE_MANIFEST=shared.CATALOG.with_name('current-image-routes-complete-20261004.json')
ROUTE_HASH='a595ef2626e23aee215f7c215f928f8f16634488e1d38cb7f866face0f6bba20'
DATA={0x11058:(8,(1<<64)-1),0x11060:(4,1),0x11064:(4,2),
    0x11068:(8,0x80000),0x11070:(8,0x2000000),0x118b8:(4,0),0x118bc:(4,0)}
IMPORTS={
    'ucrtbase_enclave.dll':{'_initterm','_initterm_e','_seh_filter_dll',
        '_initialize_onexit_table','_execute_onexit_table','_cexit','terminate',
        'free','malloc','strcpy_s','strcmp','strlen','abort','calloc'},
    'vertdll.dll':{'IsProcessorFeaturePresent','VirtualProtect','VirtualQuery','CallEnclave',
        'EnclaveRestrictContainingProcessAccess','EnclaveCopyIntoEnclave',
        'EnclaveCopyOutOfEnclave','InitializeSListHead','RtlUnwindEx','InterlockedFlushSList',
        'GetLastError','SetLastError','TlsAlloc','TlsGetValue','TlsSetValue'},
}
IMPORTS['vertdll.dll'].update({'DeleteCriticalSection','InitializeCriticalSectionEx',
    'RaiseException','RtlLookupFunctionEntry','RtlPcToFileHeader','TlsFree','VirtualAlloc','VirtualFree'})


def catalog():
    rows=shared.catalog(shared.CATALOG.read_bytes())
    pin=parallel.specification(parallel.SPEC.read_bytes())['concurrent']
    rows=rows+[dict(route='parallel_concurrent/mod.rs::open_avx2',
        image=pin['image'],sha256=pin['image_sha256'])]
    raw=ROUTE_MANIFEST.read_bytes();require(digest(raw)==ROUTE_HASH,'frozen nineteen-route matrix')
    matrix=json.loads(raw)
    expected={r['module']+'::'+r['constructor']:r['image_sha256'] for r in matrix['routes']}
    require(len(rows)==len(expected)==19 and {r['route']:r['sha256'] for r in rows}==expected,
        'exact existing nineteen routes, no omitted or invented image')
    return rows


def initialized_data(rows,address,size):
    require(type(address) is int and address>=0 and type(size) is int and 0<size<=8,
        'bounded scalar runtime data request')
    owners=[r for r in rows if r['rva']<address+size and address<r['rva']+r['virtual_size']]
    require(len(owners)==1,'unique full runtime data allocation')
    row=owners[0];offset=address-row['rva']
    require(row['flags']&0xe0000000==0xc0000000 and
        0<=offset and offset+size<=row['virtual_size'],'complete nonexecutable writable data')
    return row['code'][offset:offset+size].ljust(size,b'\0')


def initializer(code,address,selectors):
    require(set(selectors) in (set(memory.SELECTORS),{0,*memory.SELECTORS}) and
        (0 not in selectors or selectors[0]==0),'complete memory-selector identity population')
    require(len(code)==len(INIT),'complete initializer body')
    normalized=bytearray(code);targets={}
    for offset,end,role in INIT_REFS:
        target=address+end+int.from_bytes(code[offset:offset+4],'little',signed=True)
        require(role not in targets or targets[role]==target,'same original initializer data identity')
        targets[role]=target;normalized[offset:offset+4]=bytes(4)
    require(bytes(normalized)==INIT,'complete initializer instructions, not only CPUID markers')
    require(set(targets)==set(DATA),'complete selector initializer data population')
    require(all(targets[k]==v for k,v in selectors.items() if k),'initializer writes actual memory selectors')
    isa=targets[0x11060];favor=targets[0x118bc]
    require(all(targets[k]==isa+k-0x11060 for k in DATA if k<0x118b8) and
        targets[0x118b8]==favor-4,'exact separate CRT data layout')
    spans=sorted((targets[k],targets[k]+size) for k,(size,_) in DATA.items())
    require(all(a[1]<=b[0] for a,b in zip(spans,spans[1:])),'no selector identity alias')
    return targets


def isa_level(sse42,osxsave,avx,xcr0,avx2,avx512):
    """Projection of the reviewed selector writer; not CPU-migration evidence."""
    require(all(type(v) is bool for v in (sse42,osxsave,avx,avx2,avx512)) and
        type(xcr0) is int and 0<=xcr0<1<<64,'explicit public CPU feature model')
    level=2 if sse42 else 1
    if not osxsave or not avx or xcr0&6!=6:return level
    level=5 if avx2 else 3
    if avx2 and avx512 and xcr0&0xe0==0xe0:level=6
    return level


def import_check(table):
    require(set(table)==set(IMPORTS),'only the two original enclave runtime libraries')
    slots=[slot for symbols in table.values() for slot in symbols.values()]
    require(all(type(slot) is int and 0<slot<1<<32 and slot%8==0 for slot in slots) and
        len(set(slots))==len(slots),'distinct aligned IAT slots across all libraries')
    # Some scalar images omit unused compiler unwind/allocation imports. Never
    # interpret presence as execution or absence as proof of unreachability.
    for module,symbols in table.items():
        require(symbols and set(symbols)<=IMPORTS[module],'every named import explicitly classified')
        require(len(set(symbols.values()))==len(symbols),'distinct named IAT slots')
    return {module:{name:dict(iat_rva=rva,scope=(
        'OS transport/protection; exact loaded SDK contract remains final reconciliation'
        if module=='vertdll.dll' else
        'CRT import inventory only; caller reachability and loaded identity not inferred'))
        for name,rva in sorted(symbols.items())} for module,symbols in sorted(table.items())}


def inspect(image):
    rows,functions=shared.caller.pe.linked(image)
    prefix=bytes.fromhex(next(h for n,_,h in memory.prior.ANCHORS if n=='fill_rep'))
    candidates=[]
    for row in rows:
        if row['flags']&0xe0000000!=0x60000000:continue
        at=row['code'].find(prefix)
        while at!=-1:
            candidates.append(row['rva']+at+16);at=row['code'].find(prefix,at+1)
    require(len(candidates)==1,'one actual memory runtime')
    runtime=memory.inspect(image,candidates[0])
    delta=candidates[0]-memory.prior.BODIES['fill'][0]
    bodies={n:memory.prior.session.executable(rows,a+delta,size)
        for n,(a,size,_) in memory.prior.BODIES.items()}
    _,selectors,_=memory.normalize(bodies,delta)
    found=[]
    for a,b,u in functions:
        if b-a==len(INIT) and sdk.mapped(rows,a,20)==INIT[:20]:found.append((a,b,u))
    require(len(found)==1,'unique complete selector initializer runtime extent')
    a,b,u=found[0];code=sdk.mapped(rows,a,b-a)
    targets=initializer(code,a,selectors)
    for role,(size,expected) in DATA.items():
        require(int.from_bytes(initialized_data(rows,targets[role],size),'little')==expected,
            'reviewed loader initial selector value, not a live-value assertion')
    return dict(image_sha256=digest(image),runtime=runtime,
        initializer=dict(rva=a,bytes=b-a,sha256=digest(code),targets={hex(k):v for k,v in targets.items()},
            fixed_stack_bytes=24,incoming_home_saves=[16,24,32],xcr0_home_save=8,
            writes_only_public_feature_metadata=True,loaded_initialization_order_proven=False),
        startup=startup.inspect(image,a),imports=import_check(sdk.imports(image)),
        normalized_initializer_sha256=digest(INIT),loaded_application_iat_proven=False,
        native_enclave_run=False,whole_image_qualified=False)


def collect(base):
    records=[]
    for row in catalog():
        image=(base/row['image']).read_bytes()
        require(digest(image)==row['sha256'],'exact original signed image: '+row['route'])
        records.append(dict(route=row['route'],**inspect(image)))
    return dict(schema=1,status='AUTHOR_NINETEEN_IMAGE_RUNTIME_COMPONENT_REVIEW',
        completion_package=8,completion_package_closed=False,records=records,
        route_count=19,whole_image_qualified=False,new_native_enclave_run=False,
        release_gate_changed=False,independently_verified=False,
        source_sha256={p.name:digest(p.read_bytes()) for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}|{Path(__file__)})})


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('saved_directory',type=Path)
    args=parser.parse_args();print(json.dumps(collect(args.saved_directory),indent=2))
