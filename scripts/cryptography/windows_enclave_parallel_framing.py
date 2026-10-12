"""Selected sequential root framing in actual saved COFF/PE, not listing text.

Caller admission, transitive state helpers and original allocation lifetimes
remain explicit obligations. This is author review, not whole-image closure.
"""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_parallel_leaf as leaf
import windows_enclave_parallel_root_bytes as root_bytes
import windows_enclave_parallel_custom_bytes as custom_bytes
import windows_enclave_parallel_callers_bytes as callers_bytes
import windows_enclave_parallel_setup_bytes as setup_bytes

inventory=leaf.inventory
c,s=leaf.c,leaf.s
require,digest=leaf.require,leaf.digest
TABLES={lane:root_bytes.CONTRACTS[lane]|custom_bytes.CONTRACTS[lane]|
    callers_bytes.CONTRACTS[lane] for lane in ('scalar','avx2')}
for _lane in TABLES:
    _custom=TABLES[_lane]['finish_custom']
    TABLES[_lane]['finish_custom']=_custom|{
        'regions':setup_bytes.CONTRACTS[_lane]['regions']+_custom['regions'],
        'branches':setup_bytes.CONTRACTS[_lane]['branches']+_custom['branches']}
PARENTS=('finish_root','finish_custom','finish','rehash')
HANDLERS={'finish_root':36,'finish_custom':18,'finish':23,'rehash':24}


def names(functions,lane):
    result={r:s.one(functions,r'Owner\d+'+r+'$') for r in PARENTS}
    if lane=='avx2':
        result.update({r+'_handler':'?dtor$'+str(n)+'@?0?'+result[r]+'@4HA'
            for r,n in HANDLERS.items()})
    require(set(result.values())<=set(functions),'actual framing bodies and invoked funclets')
    return result


def expected_refs(functions,lane):
    n=names(functions,lane);ln=leaf.names(functions,lane);z=s.ZERO
    operation=s.one(functions,r'Owner9operation$')
    setup=s.one(functions,r'parallel_'+('stream' if lane=='scalar' else 'accelerated')+'_state.*State5setup$')
    bits=s.one(functions,r'Fips202BitString3new$')
    drop=s.one(functions,r'drop_glue.*'+('parallel_stream_state' if lane=='scalar' else 'sha3_accelerated_state')+'5StateE')
    prefix='anon.'+('e6d9992799cc35347964fcf2b37d7de4' if lane=='scalar' else '8150f061f3aeb3ba0974a94dde79d0f7')
    if lane=='scalar':
        narrow=s.one(functions,r'HardenedFips202OwnerKja8_E6update')
        wide=s.one(functions,r'HardenedFips202OwnerKj88_E6update')
        wipe=s.one(functions,r'HardenedFips202OwnerKj88_E4wipe')
        guard=s.one(functions,r'Operation.*Drop4drop$')
        result={
            'finish_root':{0x6c:z,0x7f:z,0x1c3:narrow,0x1db:z,0x1e8:z,0x20d:wide,
                0x245:s.one(functions,r'HardenedCshake12824enter_squeezing_in_place$'),
                0x255:s.one(functions,r'HardenedCshake25624enter_squeezing_in_place$'),
                0x271:z,0x2a5:s.one(functions,r'parallel_stream_state.*State7squeeze$'),
                0x2b7:drop,0x2d9:ln['encoded_drop'],0x2e6:leaf.PANIC},
            'finish_custom':{0x23:prefix+'.1',0x30:operation,0xf9:'memcpy',0x120:'memset',
                0x128:wipe,0x13e:wipe,0x14c:wipe,0x15e:z,0x206:'memcpy',0x2b0:'memcpy',
                0x2d7:'memset',0x2df:wipe,0x2f5:wipe,0x303:wipe,0x315:z,0x3bd:'memcpy',
                0x3db:drop,0x42d:'memcpy',0x477:z,0x48a:z,0x5d4:narrow,0x5eb:wipe,
                0x5f9:wipe,0x60b:z,0x640:guard,0x66a:wide,0x67d:z,0x68a:z,0x6cb:bits,
                0x72c:ln['finish'],0x73d:z,0x769:n['finish_root'],0x785:ln['encoded_drop'],
                0x79a:leaf.PANIC},
            'finish':{0x24:prefix+'.4',0x2e:operation,0xd5:ln['finish'],
                0xe7:n['finish_root'],0xf7:guard},
            'rehash':{0x2b:prefix+'.5',0x35:operation,0xcb:drop,0xe4:z,0xf5:z,0x106:z,
                0x158:setup,0x18c:'memcpy',0x194:drop,0x1b2:'memcpy',0x209:guard}}
    else:
        clear=s.one(functions,r'Owner5clear$');state=leaf.STATE
        result={
            'finish_root':{0x76:z,0x89:z,0x1b6:state+'6update',0x1d0:z,0x1de:z,
                0x21c:state+'10finish_xof',0x232:z,0x271:state+'7squeeze',0x28e:drop,
                0x2b7:ln['encoded_drop'],0x2c4:leaf.PANIC},
            'finish_custom':{0x35:prefix+'.1',0x3e:operation,
                0xa4:s.one(functions,r'sha3_accelerated_state.*Memory4wipe$'),0xc1:z,
                0x128:clear,0x208:z,0x25c:z,0x269:z,0x385:state+'6update',0x3d5:bits,
                0x416:ln['finish'],0x42e:z,0x45a:n['finish_root'],0x477:ln['encoded_drop'],
                0x497:z,0x4a4:z,0x4b8:leaf.PANIC},
            'finish':{0x2f:prefix+'.4',0x38:operation,0xdb:ln['finish'],
                0xef:n['finish_root'],0x125:clear},
            'rehash':{0x4c:prefix+'.5',0x58:operation,0xed:drop,0x109:z,0x11a:z,0x12b:z,
                0x18c:setup,0x1d9:clear,0x216:'memcpy',0x24b:drop,0x271:'memcpy'},
            'finish_root_handler':{0x1e:ln['encoded_drop']},
            'finish_custom_handler':{0x21:ln['encoded_drop'],0x4f:clear},
            'finish_handler':{0x3d:clear},'rehash_handler':{0x4d:clear}}
    return result


def refs_check(bodies,refs,expected):
    require(set(bodies)==set(refs)==set(expected),'complete selected framing reference population')
    for role,targets in expected.items():
        rows=refs[role]
        require(len(rows)==len(targets) and {r['offset']:r['symbol'] for r in rows}==targets,
            'each framing reference has its reviewed semantic target')
        for r in rows:
            at=r['offset'];is_data=r['symbol'].startswith('anon.')
            opcode=b'\x4c\x8d\x0d' if is_data else b'\xe8'
            require(r['trailing']==r['addend']==0 and
                bodies[role][at-len(opcode):at+4]==opcode+bytes(4),
                'framing direct call/data address without hidden adjustment')


def instructions(bodies,lane):
    require(set(bodies)==set(TABLES[lane]),'no omitted framing function or funclet')
    count=0
    for role,contract in TABLES[lane].items():
        code=bodies[role]
        require(len(code)==contract['size'],'actual framing extent, not listing extent')
        anchors=[(at,text) for _,at,text in contract['regions']]
        cursor=0
        for at,text in anchors:
            require(at==cursor,'no omitted or overlapping framing instruction span')
            cursor+=len(bytes.fromhex(text))
        require(cursor==len(code),'complete selected framing byte coverage')
        leaf.finish.windows(code,anchors,contract['branches'])
        count+=sum(len(bytes.fromhex(text)) for _,text in anchors)
    return count


def phase_data(image,records,selected,expected):
    result={}
    for role,value in (('finish_custom',b'\x01\x02'),('finish',b'\x03'),('rehash',b'\x05\x06')):
        symbol=next(v for v in expected[role].values() if v.startswith('anon.'))
        rva=records[selected[role]]['reference_targets'][symbol]
        require(c.previous.readonly(image,rva,len(value))==value,'actual immutable allowed-phase data')
        result[role]=list(value)
    return result


def geometry(lane):
    # Relative to an already-valid, exclusively borrowed Owner. Placement and
    # authority lifetime are not established by this relative geometry check.
    if lane=='scalar':
        return dict(root=[0,0x470],input=[0x470,0x920],output=[0x920,0xd20],
            metadata=[0xd20,0xd60],width=0xd40,last=0xd51,next_width=0xd48,next_last=0xd52)
    return dict(root=[0x840,0xc20],input=[0x400,0x840],output=[0,0x400],
        metadata=[0xc20,0xc60],width=0xc40,last=0xc58,next_width=0xc48,next_last=0xc59)


def inspect_route(base,root,lane,pin,mutate):
    import windows_enclave_parallel_framing_models as models
    inputs,sources=inventory.load(base,root,pin)
    functions=c.previous.inventory(inputs['object']);inventory.functions_check(functions,pin)
    records=c.previous.bind_all(inputs['object'],inputs['image'],functions)
    selected=names(functions,lane);expected=expected_refs(functions,lane)
    bodies={r:functions[n][0] for r,n in selected.items()}
    refs={r:functions[n][1] for r,n in selected.items()}
    refs_check(bodies,refs,expected);count=instructions(bodies,lane)
    phases=phase_data(inputs['image'],records,selected,expected)
    geometry_report=models.relative_regions(lane)
    return_graph=models.root_return_graph(bodies['finish_root'],lane)
    transfer=models.scalar_setup_copy_geometry() if lane=='scalar' else {
        'setup_completed_in_place':True,'authority_and_exact_customization_checked':True,
        'original_authority_lifetime_established_here':False}
    if lane=='avx2':
        for role in PARENTS:
            handler=selected[role+'_handler']
            require(any(m['symbol']==handler and m['target_rva']==records[handler]['rva']
                for m in records[selected[role]].get('metadata',[])),
                'actual enclosing xdata binds invoked framing cleanup')
    mutations=0
    if mutate:
        for role,name in selected.items():
            code,relocations,kind=functions[name]
            for at in range(len(code)):
                bad=bytearray(code);bad[at]^=1
                try:c.body_check((bad,relocations,kind),pin['functions'][name])
                except ValueError:mutations+=1
                else:raise AssertionError('accepted framing body mutation')
    return dict(object_sha256=digest(inputs['object']),image_sha256=digest(inputs['image']),
        source_sha256=sources,entries={r:records[n] for r,n in selected.items()},
        allowed_phases=phases,relative_owner_regions=geometry_report,root_return_graph=return_graph,
        setup_transfers=transfer,
        reviewed_instruction_bytes=count,body_byte_mutations_rejected=mutations,
        semantics=dict(output_bits='(width-1)*8+last, or zero for empty output',
            suffix='right_encode(L); XOF callers require width=last=0',
            prefix='left_encode(B), u64 B, at most nine bytes',
            leaf_completion_precedes_root_finalization=True,
            retained_input_consumed_before_full_1024_byte_clear=True,
            next_shape_loaded_before_metadata_reset=True,
            phase_published_only_after_success=True,invoked_handlers_bound=(lane=='avx2'),
            model_is_machine_execution=False),assembly_listing_used_for_semantics=False,
        complete_sequential_path=False,remaining=['earlier private-frame copies require full window retirement',
            'transitive state helpers, original allocations and authority lifetimes',
            'outer caller, export/cancellation and complete resident/page retirement',
            'shared runtime ABI, earlier frame copies and full window clearing: package 8'])


def inspect(base,root,mutate=False):
    spec=inventory.specification(inventory.SPEC.read_bytes())
    routes={lane:inspect_route(base,root,lane,spec[lane],mutate) for lane in TABLES}
    return dict(schema=1,status='AUTHOR_SELECTED_PARALLELHASH_ROOT_FRAMING',routes=routes,
        completion_package=7,pass_number=2,pass_complete=False,completion_package_closed=False,
        whole_image_qualified=False,independently_verified=False,new_native_run=False,
        release_gate_changed=False,shared_runtime_window_package=8,
        source_sha256={p.name:digest(p.read_bytes()) for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}|{Path(__file__)})})


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path)
    p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path)
    args=p.parse_args();result=inspect(args.saved_directory,args.source_root,args.mutate)
    text=json.dumps(result,indent=2)+'\n'
    if args.output:args.output.write_text(text,encoding='utf-8')
    else:print(text,end='')
