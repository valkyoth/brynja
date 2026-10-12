"""Saved sequential request/export review; not complete ParallelHash qualification.

Literal machine-code spans and table destinations are bound to the actual COFF
and signed PE, not the separately emitted listing. C/OS copying, caller-window
retirement and transitive owner/state semantics remain separate obligations.
"""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_parallel_lifecycle as life
import windows_enclave_parallel_entry as entry
import windows_enclave_parallel_scalar_request_bytes as scalar
import windows_enclave_parallel_avx2_request_bytes as avx2
import windows_enclave_sha3_operations as table_review

inventory,c,s=life.inventory,life.c,life.s
require,digest=life.require,life.digest
TABLES={'scalar':scalar.CONTRACTS,'avx2':avx2.CONTRACTS}
OPERATIONS=('begin','custom','setup','update','finish','squeeze','export','cancel','rehash')
# Explicit operation order, independently reviewed at each indirect branch.
DESTINATIONS={
    'scalar':{'receive':[[0x199,0x1e0,0x1e0,0x1c3,0x1e0,0x1e0,0x199,0x1e0,0x199],
        [0x2fd,0x3e5,0x3af,0x3bf,0x335,0x455,0x473,0x3d5,0x4a7]]},
    'avx2':{'receive':[[0x13a,0x1f7,0x1ca,0x1d7,0x156,0x263,0x27a,0x1ea,0x328]],
        'decode':[[0x146,0x180,0x180,0x168,0x180,0x180,0x146,0x180,0x146]]}}
OPERANDS={'scalar':{'receive':[[0x18b,0],[0x2f0,36]]},
    'avx2':{'receive':[[0x12b,0]],'decode':[[0x137,0]]}}


def names(functions,lane):
    result={'receive':s.one(functions,r'worker7receive$')}
    if lane=='avx2':
        result.update(decode=s.one(functions,r'Header6decode$'),
            authority=s.one(functions,r'15check_authority$'))
    require(set(result)==set(TABLES[lane]),'exact request body population')
    return result


def expected_refs(functions,lane):
    n=names(functions,lane)
    owner={role:s.one(functions,r'Owner\d+'+role+'$') for role in
        ('begin','finish','finish_custom','update','cancel','custom','squeeze','operation','rehash','clear')}
    bits=s.one(functions,r'Fips202BitString3new$')
    if lane=='scalar':
        guard=s.one(functions,r'Operation.*Drop4drop$')
        calls={0x1d:'PublicParallelSource',0x36:'PublicParallelInput',0x2c3:'PublicParallelInput',
            0x32c:owner['begin'],0x347:bits,0x3a6:owner['finish'],0x3b6:owner['finish_custom'],
            0x3cc:owner['update'],0x3dc:owner['cancel'],0x3f7:bits,0x44c:owner['custom'],
            0x46d:owner['squeeze'],0x48f:owner['operation'],0x4e5:owner['rehash'],
            0x4f5:guard,0x543:'PublicParallelOutput',0x551:guard,0x561:guard,
            0x579:s.ZERO,0x59a:owner['clear']}
        data={0x18b:('.rdata',0),0x2f0:('.rdata',36),
            0x47f:('anon.e6d9992799cc35347964fcf2b37d7de4.5',0)}
    else:
        calls={0x1a:'PublicParallelSource',0x36:'PublicParallelInput',0x4e:n['decode'],
            0x8e:'PublicParallelInput',0xad:n['decode'],0x14d:owner['begin'],0x168:bits,
            0x1c1:owner['finish'],0x1ce:owner['finish_custom'],0x1e1:owner['update'],
            0x1ee:owner['cancel'],0x209:bits,0x25a:owner['custom'],0x271:owner['squeeze'],
            0x299:owner['operation'],0x2dd:'PublicParallelOutput',0x2ed:n['authority'],
            0x31b:owner['clear'],0x345:owner['rehash'],0x369:owner['clear'],
            0x3a1:s.ZERO,0x3c2:owner['clear']}
        data={0x9d:('_RNvCs6vN7PGL8mdd_27parallel_accelerated_worker4LIVE',16),
            0x12b:('.rdata',0),0x289:('anon.8150f061f3aeb3ba0974a94dde79d0f7.5',0)}
    refs=[dict(offset=at,symbol=sym,addend=0,trailing=0) for at,sym in calls.items()]
    refs += [dict(offset=at,symbol=sym,addend=add,trailing=0) for at,(sym,add) in data.items()]
    result={'receive':sorted(refs,key=lambda r:r['offset'])}
    if lane=='avx2':
        result.update(decode=[dict(offset=0x137,symbol='.rdata',addend=0,trailing=0)],authority=[])
    return result


def refs_check(bodies,refs,expected):
    require(refs==expected and set(bodies)==set(expected),'exact request call/data population and operands')
    for role,rows in refs.items():
        for row in rows:
            at=row['offset'];name=row['symbol'];code=bodies[role]
            require(int.from_bytes(code[at:at+4],'little',signed=True)==row['addend'],
                'exact relocation operand before linking')
            if name=='.rdata' or name.startswith('anon.'):
                require(code[at-2]==0x8d,'reviewed RIP-relative data address')
            elif name.endswith('4LIVE'):
                require(code[at-3:at]==bytes.fromhex('488b35'),'original resident owner pointer load')
            else:require(code[at-1]==0xe8,'direct call, not pointer dispatch')


def instructions(bodies,lane):
    require(set(bodies)==set(TABLES[lane]),'complete selected request bodies')
    for role,contract in TABLES[lane].items():
        code=bodies[role];cursor=0;anchors=[]
        require(len(code)==contract['size'],'exact request body extent')
        for label,at,text in contract['regions']:
            require(label and at==cursor,'complete named instruction coverage')
            cursor+=len(bytes.fromhex(text));anchors.append((at,text))
        require(cursor==len(code),'no omitted request or export bytes')
        life.framing.leaf.finish.windows(code,anchors,contract['branches'])
    return sum(map(len,bodies.values()))


def table_pin(lane,role):
    # COFF addends encode target relative to each table relocation word; machine
    # dispatch adds its subtable base. Do not confuse the two scalar tables.
    raw=bytearray()
    for targets in DESTINATIONS[lane][role]:
        require(len(targets)==len(OPERATIONS),'nine operation destinations')
        for index,target in enumerate(targets):raw.extend((target+index*4+4).to_bytes(4,'little'))
    return dict(operands=OPERANDS[lane][role],object_hex=raw.hex(),
        subtable_bytes=[36]*len(DESTINATIONS[lane][role]))


def tables_check(inputs,records,selected,lane):
    result={}
    for role,targets in DESTINATIONS[lane].items():
        _,bound=table_review.table(inputs['object'],inputs['image'],records[selected[role]],table_pin(lane,role))
        require(bound['destinations']==[v for table in targets for v in table],
            'actual linked branches preserve operation identities')
        result[role]=bound
    return result


def phases_and_identity(image,records,selected,lane):
    rec=records[selected['receive']]
    symbols=[n for n in rec['reference_targets'] if n.startswith('anon.')]
    require(len(symbols)==1,'one export phase constant')
    require(c.previous.readonly(image,rec['reference_targets'][symbols[0]],2)==b'\x05\x06',
        'export only from Retained or More')
    if lane=='avx2':
        live='_RNvCs6vN7PGL8mdd_27parallel_accelerated_worker4LIVE'
        require(rec['reference_targets'][live]==records['RetainedWork']['reference_targets'][live],
            'same original placed-resident handle as outer entry')
    return [5,6]


def inspect(base,root,mutate=False):
    import windows_enclave_parallel_request_models as models
    spec=inventory.specification(inventory.SPEC.read_bytes());routes={}
    for lane in TABLES:
        inputs,sources=inventory.load(base,root,spec[lane])
        functions=c.previous.inventory(inputs['object']);inventory.functions_check(functions,spec[lane])
        records=c.previous.bind_all(inputs['object'],inputs['image'],functions)
        n=names(functions,lane);bodies={r:functions[name][0] for r,name in n.items()}
        refs={r:functions[name][1] for r,name in n.items()}
        refs_check(bodies,refs,expected_refs(functions,lane));count=instructions(bodies,lane)
        geometry=models.export_operands(bodies,lane)
        tables=tables_check(inputs,records,n,lane)
        phases=phases_and_identity(inputs['image'],records,n,lane)
        identity=entry.global_storage(inputs['image'],records['RetainedWork'],lane)
        mutations=0
        if mutate:
            for role,name in n.items():
                code,relocs,kind=functions[name]
                for at in range(len(code)):
                    bad=bytearray(code);bad[at]^=1
                    try:c.body_check((bad,relocs,kind),spec[lane]['functions'][name])
                    except ValueError:mutations+=1
                    else:raise AssertionError('accepted request body mutation')
        routes[lane]=dict(object_sha256=digest(inputs['object']),image_sha256=digest(inputs['image']),
            source_sha256=sources,entries={r:records[name] for r,name in n.items()},
            dispatch_tables=tables,export_phases=phases,identity_storage=identity,export_geometry=geometry,
            reviewed_instruction_bytes=count,body_byte_mutations_rejected=mutations,
            semantics=dict(header_bytes=112 if lane=='scalar' else 128,payload_limit=1024,
                header_before_payload=True,local_header_redecoded=lane=='avx2',
                payload_pointer_passed_only_to_fixed_transport=True,
                exact_export_identity_width_last=True,entire_1024_output_erased_on_success=True,
                authority_rechecked_after_copy=lane=='avx2',copy_failure_rollback_proved=False,
                full_caller_frame_erasure_proved=False,normal_return_callee_contracts_assumed=True),
            remaining=['transitive owner/state, KAT, permutation and destructor composition',
                'C serialization, fixed transport copy behavior, exclusive original allocations',
                'whole private-window and exceptional retirement; package 08'])
    return dict(schema=1,status='AUTHOR_SELECTED_PARALLELHASH_REQUEST_EXPORT',routes=routes,
        completion_package=7,pass_number=2,pass_complete=False,completion_package_closed=False,
        whole_image_qualified=False,independently_verified=False,new_native_run=False,release_gate_changed=False,
        source_sha256={p.name:digest(p.read_bytes()) for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}|{Path(__file__)})})


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('saved_directory',type=Path)
    parser.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
    parser.add_argument('--mutate',action='store_true');args=parser.parse_args()
    print(json.dumps(inspect(args.saved_directory,args.source_root,args.mutate),indent=2))
