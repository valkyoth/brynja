"""Normal compute-window/storage composition for the saved 08A canary only.

SDK/bootstrap depth, incoming registers, OS transitions and arbitrary exceptions
remain explicit exclusions. This does not qualify a secret transport boundary.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

import windows_enclave_transport_review as transport
import windows_enclave_outer_window as outer

resident,bridge,require=transport.resident,transport.bridge,transport.require
digest=lambda raw:hashlib.sha256(raw).hexdigest()
WRAPPER='88c9c0d9419e178f50810c1d20cace767adcbdfd68831e3c7ece6eb146e0e3db'
PINS={
    'PublicLockedWindow':('f6e3d884c04f8ff5312153423490f1e7b1ce97f17c8a74532ccc8e99a100bd9a',
        '85a46435fa6fce227d1a773c1a06820575b0f68959e446532dfa2f7fb19fb776'),
    'PublicLockedFinish':('6ce889882a081e3c1eca1fa62282be1876eaac9f5d53e95fa367b58830e0f3f6',
        'd3a315522e10e98cc21d1da4812bba130fcf310abae8e85386c07f43dc031690'),
    'PublicGuardRestore':('676fb391a0a2b23f3fa173844f5463aeb3e8d0b99da2b0c110849a4f02ad6cbf',
        'a5d05d1c39a0fbb78b8aa0d3c3f2dbe4ae3b434e0fe5a3b2ff10694612e48f79'),
    'PublicLockedAdmit':('669e46ed7445b65b9bae313c3040e98872ed621b82c2ab98182ab7630c3cb387',
        '9bc65285e471b7fa6f241158a6a2d15516459a5641d0da9e2354536d2927bdf8'),
    'page_info':('45f45756772e9ad5d8bb3c9c61561c3860c14728d44fa0aa53011201836b775d',
        '8221bff1697a5c302a0fe359bfed782bae5c5ddb6ebebea0c94813bd76dac0a9'),
    'notify_host':('f5604b66a26282fd8ea72574ec48f6f7d514097e73d66505b1632bd639209ec4',
        'a6e705c755a73a767ae7f573505666368fc04111905fdb633eb79a89844fc405'),
}
SIZES=dict(busy=4,active=4,stage_attempted=4,stage_admitted=4,low_changed=4,high_changed=4,
    low_old=4,high_old=4,stage_region=8,host_callback=8,released=8,retired=8,last_status=8,
    published=8,body_calls=8,request=32,cleared=8,admitted=8,handler_address=8,
    marker_address=8,steps=8,stats=96,PublicLockedLow=8,PublicLockedHigh=8)


def bind(obj,image,name,rva):
    raw,refs,targets=bridge.bind(obj,image,name,rva)
    require((digest(raw),digest(json.dumps(refs,sort_keys=True).encode()))==PINS[name],
            'complete canary boundary helper '+name)
    return dict(rva=rva,size=len(raw),reference_targets=targets)


def wrapper_contract(raw,code,rva):
    require(len(raw)==399 and digest(raw)==WRAPPER,'exact fatal-on-dirty wrapper variant')
    # The fatal retry after INT29 is deliberately unreachable under the normal
    # terminal-trap model; do not force it into the normal-return CFG.
    edges,calls={},{}
    for at,(instruction,text) in code.items():
        op=text.split(' ',1)[0]
        if instruction==b'\xcd\x29' or op=='retq': edges[at]=[]
        elif op.startswith('j'):
            target=resident.review.decode.relative(instruction,at)
            edges[at]=[target] if op in ('jmp','jmpq') else [target,at+len(instruction)]
        else:
            require(not op.startswith(('int','iret','sys','loop')),'no other exceptional transfer')
            edges[at]=[at+len(instruction)]
            if op=='callq': calls[at]=resident.review.decode.relative(instruction,rva+at)
        require(all(target in code for target in edges[at]),'complete wrapper CFG')
    require(code[0x141][0]==b'\xcd\x29' and code[0x143][0]==b'\xeb\xf7',
            'dirty readback is fatal, never a success path')
    require(set(calls)=={0x4a,0x7c,0xb2,0x135,0x149},'only reviewed five calls')
    require([at for at,(_,text) in code.items() if text=='retq']==[0x18e],'one normal return')
    required=(0xbf,0xc9,0xcd,0xd1,0xd5,0xd9,0xdd,0xe1,0xe3,0xe5,0xe7,0xea,0xed,
              0x107,0x11d,0x129,0x135,0x149,0x157,0x161,0x165,0x169,0x16d,0x171,
              0x175,0x179,0x17b,0x17d,0x180,0x183,0x186)
    for at in required:
        require(outer.dominates(edges,0,at,0x18e),'normal return requires retirement step')
    require(not outer.dominates(edges,0,0xb2,0x18e),'denied admission can reclaim without compute')
    require(outer.dominates(edges,0,0x12c,0x135),'finish only after readback branch')
    require(code[0x12c][0]==bytes.fromhex('750e') and edges[0x12c]==[0x13c,0x12e],
            'dirty branch cannot reach finish/restore')
    # Complete hashes bind the loop setup/stride and AVX admission sequence;
    # these explicit anchors make the reviewed semantics independently visible.
    for at,expected in ((0x43,'48c7c020400100'),(0x107,'498902'),(0x10a,'4983c208'),
                        (0x111,'72f4'),(0x11d,'4d0b0a'),(0x120,'4983c208'),(0x127,'72f4'),
                        (0xc6,'c5f877'),(0x15e,'c5f877')):
        require(code[at][0]==bytes.fromhex(expected),'exact extent/stride/register instruction')
    return dict(normal_return=0x18e,required_instructions=list(required),calls=sorted(calls),
        dirty_readback_terminal=True,denial_reclaims=True,clear_bytes=65536,clear_words=8192,
        xmm_low_halves_cleared=list(range(6)),nonvolatile_xmm_low_halves_preserved=list(range(6,16)),
        ymm_upper_clear_requires_cached_avx_os_admission=True,incoming_registers_proven_public=False,
        avx512_or_extended_register_cleanup_claimed=False)


def geometry(rbp,bound=2544):
    require(type(rbp) is int and 81952<rbp<(1<<64)-4096 and rbp%16==0,'bounded aligned RBP')
    require(type(bound) is int and 0<=bound<=65536-40,'complete normal compute fits window')
    high=(rbp&-4096)-4096
    low=high-65536
    bootstrap=low-4128
    require(rbp-81952<=bootstrap-8 and high+4096<=rbp,'probe reaches bootstrap call slot')
    # CALL PublicRustBody from H-32 enters at H-40. The adapter tail-jumps;
    # the composed bound already includes the Rust chain below that entry.
    require(low<=high-40-bound and high-40+40==high,'complete chain plus entry/home fits')
    return dict(window_low=low,window_high=high,bootstrap=bootstrap,
        compute_entry=high-40,compute_entry_residue=(high-40)%32,
        compute_low=high-40-bound,depth_from_window_high=40+bound,
        probed_low=rbp-81952,probe_is_not_sdk_depth_bound=True,
        home_slots=dict(argument=rbp+16,result=rbp+24,avx_flag=rbp+32),
        private_home_is_not_secret_storage=True)


def storage(image,targets):
    rows,_=bridge.caller.pe.linked(image)
    require(set(SIZES)<=set(targets),'complete named control storage')
    spans=[]
    for name,size in SIZES.items():
        at=targets[name]
        require(any(row['flags']&0xe0000000==0xc0000000 and row['rva']<=at
            and at+size<=row['rva']+row['virtual_size'] for row in rows),'owned nonexecuting control '+name)
        spans.append(dict(name=name,rva=at,bytes=size))
    spans.sort(key=lambda row:row['rva'])
    require(all(a['rva']+a['bytes']<=b['rva'] for a,b in zip(spans,spans[1:])),
            'full-sized controls and descriptor never overlap')
    return spans


def inspect(directory,text,sdk):
    prior=transport.inspect(directory,text,sdk)
    image=(directory/'signed.dll').read_bytes()
    obj=(directory/'normal.obj').read_bytes()
    wrapper=prior['compute']['wrapper']
    raw,_=bridge.caller.pe.coff((directory/'window.obj').read_bytes(),'PublicLockedFrame')
    ins=resident.review.decode.parse(text)
    code=resident.review.decode.body(image,wrapper,ins)
    contract=wrapper_contract(raw,code,wrapper['rva'])
    targets=dict(prior['root']['reference_targets'])
    for name,at in wrapper['global_target_rvas'].items(): bridge.identity(targets,name,at)
    for name,at in wrapper['call_target_rvas'].items(): bridge.identity(targets,name,at)
    helpers={}
    for name in ('PublicLockedWindow','PublicLockedAdmit','PublicLockedFinish','PublicGuardRestore',
                 'page_info','notify_host'):
        record=bind(obj,image,name,targets[name])
        helpers[name]=record
        for symbol,at in record['reference_targets'].items(): bridge.identity(targets,symbol,at)
    require(targets['PublicLockedFrame']==wrapper['rva'],'actual entry-to-wrapper connection')
    table=bridge.sdk.imports(image)['vertdll.dll']
    for name,at in targets.items():
        if name.startswith('__imp_'): require(table[name[6:]]==at,'real boundary IAT '+name)
    # Only the finite SDK-free chain gets a complete bound. Helpers above run
    # outside it; their OS/diagnostic callee depths remain unresolved.
    bound=prior['compute']['normal_compute_bound']['24']
    require(bound['finite_transitive_bound_proven'] and not bound['unresolved_boundaries'],
            'real entry residue selects a complete compute chain')
    layouts=[geometry(0x100000+i,bound['complete_stack_bytes']) for i in range(0,4096,16)]
    require(all(row['compute_entry_residue']==24 and row['depth_from_window_high']==2584
                for row in layouts),'all aligned RBP page residues')
    return dict(schema=1,status='AUTHOR_CANARY_NORMAL_WINDOW_AND_CONTROL_STORAGE_COMPOSITION',
        image_sha256=prior['image_sha256'],disassembly_sha256=digest(text.encode()),
        wrapper=wrapper,contract=contract,helpers=helpers,control_storage=storage(image,targets),
        compute_depth_from_high=2584,aligned_page_residues=len(layouts),
        staging_lifetime_evidence='previous pinned root, full-page retirement and trusted-host phase checks',
        fresh_os_allocation_disjointness_is_platform_precondition=True,
        complete_brynja_normal_compute_window_bound=True,whole_thread_stack_bound=False,
        incoming_register_payload_provenance=False,sdk_transport_payload_handling_qualified=False,
        asynchronous_exception_cleanup_qualified=False,whole_image_qualified=False,
        completion_package_closed=False,production_qualified=False,new_native_execution=False,
        source_sha256={p.name:digest(p.read_bytes()) for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
            |{Path(__file__)})})


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--sdk',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(inspect(args.directory,(args.directory/'disassembly.txt').read_text(),
                            args.sdk.read_bytes()),indent=2))
