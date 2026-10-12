"""Selected sequential admission, cancellation and placed-resident retirement.

Actual COFF/PE contracts, conditional on typed callees and the original exclusive
page/private-window admission. Neither exceptional full-page retirement nor
complete outer-worker/transport qualification is claimed by these checks.
"""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_parallel_framing as framing
import windows_enclave_parallel_scalar_lifecycle_bytes as scalar_bytes
import windows_enclave_parallel_avx2_lifecycle_bytes as avx2_bytes

inventory,c,s=framing.inventory,framing.c,framing.s
require,digest=framing.require,framing.digest
TABLES={'scalar':scalar_bytes.CONTRACTS,'avx2':avx2_bytes.CONTRACTS}


def names(functions,lane):
    result={r:s.one(functions,r'Owner\d+'+r+'$') for r in ('clear','operation','cancel')}
    if lane=='scalar':
        result.update(quarantine=s.one(functions,r'Owner10quarantine$'),
            guard=s.one(functions,r'Operation.*Drop4drop$'))
    else:
        result.update(new=s.one(functions,r'Resident3new$'),
            drop=s.one(functions,r'Resident.*Drop4drop$'))
        result.update(cancel_handler='?dtor$2@?0?'+result['cancel']+'@4HA',
            drop_handler='?dtor$8@?0?'+result['drop']+'@4HA')
    require(set(result)==set(TABLES[lane]) and set(result.values())<=set(functions),
        'exact lifecycle population, including actual invoked handlers')
    return result


def expected_refs(functions,lane):
    n=names(functions,lane);z=s.ZERO
    drop=s.one(functions,r'drop_glue.*'+('parallel_stream_state' if lane=='scalar'
        else 'sha3_accelerated_state')+'5StateE')
    if lane=='scalar':
        def clears(drops,wipes):return {at:drop for at in drops}|{at:z for at in wipes}
        return dict(clear=clears((0xe,0x1d),(0x35,0x46,0x57,0x72,0x95)),
            quarantine=clears((0xe,0x1d),(0x35,0x46,0x57,0x72,0x95)),
            guard=clears((0x17,0x26),(0x3e,0x4f,0x60,0x7b,0x9e)),
            operation=clears((0x40,0x4f,0x109,0x118),
                (0x67,0x78,0x89,0xa4,0xc7,0x130,0x141,0x152,0x16d,0x190)),
            cancel={0x1c:'anon.e6d9992799cc35347964fcf2b37d7de4.3',0x26:n['operation']}|
                clears((0x44,0x53),(0x6b,0x7c,0x8d,0xa8,0xcb)))
    state_drop=s.one(functions,r'drop_glue.*parallel_accelerated_state5StateE')
    input_drop=s.one(functions,r'drop_glue.*parallel_accelerated_input5InputE')
    return dict(clear={0x1f:drop,0x3f:drop,0x5b:z,0x6c:z,0x7d:z,0x96:z,0xb9:z},
        operation={at:n['clear'] for at in (0x4b,0x82,0x13f)},
        cancel={0x25:'anon.8150f061f3aeb3ba0974a94dde79d0f7.3',
            0x2e:n['operation'],0x4c:n['clear']},cancel_handler={0x35:n['clear']},
        new={0xd:'__chkstk',0x1b:s.one(functions,r'operations12known_answer$'),
            0x6a:'memset',0xa6:'memcpy',0x12e:'memcpy'},
        drop={0x38:n['clear'],0x50:state_drop,0x68:drop,0x84:z,0x95:z,0xa6:z,0xba:state_drop},
        drop_handler={0x1d:state_drop,0x2c:input_drop})


def instructions(bodies,lane):
    require(set(bodies)==set(TABLES[lane]),'complete selected lifecycle population')
    count=0
    for role,contract in TABLES[lane].items():
        code=bodies[role];require(len(code)==contract['size'],'exact lifecycle extent')
        cursor=0;anchors=[]
        for label,at,text in contract['regions']:
            require(label and at==cursor,'no unassigned or overlapping lifecycle span')
            cursor+=len(bytes.fromhex(text));anchors.append((at,text))
        require(cursor==len(code),'complete selected lifecycle byte coverage')
        framing.leaf.finish.windows(code,anchors,contract['branches']);count+=cursor
    return count


def handlers_check(records,selected):
    for parent in ('cancel','drop'):
        handler=selected[parent+'_handler']
        require(any(m['symbol']==handler and m['target_rva']==records[handler]['rva']
            for m in records[selected[parent]].get('metadata',[])),
            'actual parent xdata binds lifecycle handler')


def cancellation_phases(image,records,selected,expected):
    symbol=next(v for v in expected['cancel'].values() if v.startswith('anon.'))
    rva=records[selected['cancel']]['reference_targets'][symbol]
    value=c.previous.readonly(image,rva,6)
    require(value==bytes(range(1,7)),'cancel admits exactly six nonempty nonquarantined phases')
    return list(value)


def inspect_route(base,root,lane,pin,mutate):
    import windows_enclave_parallel_lifecycle_models as models
    import windows_enclave_parallel_entry as entry
    inputs,sources=inventory.load(base,root,pin)
    functions=c.previous.inventory(inputs['object']);inventory.functions_check(functions,pin)
    records=c.previous.bind_all(inputs['object'],inputs['image'],functions)
    selected=names(functions,lane);expected=expected_refs(functions,lane)
    bodies={r:functions[n][0] for r,n in selected.items()}
    refs={r:functions[n][1] for r,n in selected.items()}
    framing.refs_check(bodies,refs,expected);count=instructions(bodies,lane)
    phases=cancellation_phases(inputs['image'],records,selected,expected)
    placement=None
    if lane=='avx2':
        handlers_check(records,selected)
        placement=models.placement(bodies['new'])
        placement['failure_page_clear']=models.page_loop(bodies['new'],0x1de,0x07)
        placement['normal_drop_page_clear']=models.page_loop(bodies['drop'],0xbe,0x06)
        placement['normal_retirement_graph']=models.retirement_graph(bodies['drop'])
    mutations=0
    if mutate:
        for role,name in selected.items():
            code,relocations,kind=functions[name]
            for at in range(len(code)):
                bad=bytearray(code);bad[at]^=1
                try:c.body_check((bad,relocations,kind),pin['functions'][name])
                except ValueError:mutations+=1
                else:raise AssertionError('accepted lifecycle body mutation')
    return dict(object_sha256=digest(inputs['object']),image_sha256=digest(inputs['image']),
        source_sha256=sources,entries={r:records[n] for r,n in selected.items()},
        outer_entry=entry.inspect_loaded(inputs,functions,records,lane,pin,mutate),
        cancel_allowed_phases=phases,placement=placement,
        reviewed_instruction_bytes=count,body_byte_mutations_rejected=mutations,
        semantics=dict(sequence_committed_only_after_admission=True,
            cancellation_clears_before_empty_publication=True,
            authority_revoked_on_invalid_operation=(lane=='avx2'),
            clear_preserves_sequence=True,clear_is_full_page_erasure=False,
            resident_exception_handler_clears_full_page=False,
            shared_runtime_and_private_window_package=8),
        complete_sequential_path=False,assembly_listing_used_for_semantics=False,
        remaining=['request/export and transitive owner/state composition',
            'transitive state destructor, KAT and runtime/copy helper contracts',
            'original exclusive admitted page/private window and full stack retirement',
            'exceptional page/window retirement is not proved by normal-path wiping'])


def inspect(base,root,mutate=False):
    spec=inventory.specification(inventory.SPEC.read_bytes())
    routes={lane:inspect_route(base,root,lane,spec[lane],mutate) for lane in TABLES}
    return dict(schema=1,status='AUTHOR_SELECTED_PARALLELHASH_LIFECYCLE',routes=routes,
        completion_package=7,pass_number=2,pass_complete=False,completion_package_closed=False,
        whole_image_qualified=False,independently_verified=False,new_native_run=False,
        release_gate_changed=False,
        source_sha256={p.name:digest(p.read_bytes()) for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}|{Path(__file__)})})


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('saved_directory',type=Path)
    parser.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
    parser.add_argument('--mutate',action='store_true');args=parser.parse_args()
    print(json.dumps(inspect(args.saved_directory,args.source_root,args.mutate),indent=2))
