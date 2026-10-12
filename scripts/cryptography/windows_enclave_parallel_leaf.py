"""Selected sequential ParallelHash leaf review against actual COFF/PE bytes.

This advances pass 2, but does not close the sequential caller/state population,
package 7 or whole-image qualification. No release-gate policy is changed.
"""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_parallel_inventory as inventory
import windows_enclave_parallel_leaf_finish as finish
import windows_enclave_parallel_leaf_flush as flush
import windows_enclave_parallel_leaf_absorb as absorb

c=inventory.common
s=c.shapes
require,digest=inventory.require,inventory.digest
ROLES={'finish':r'Input6finish$', 'flush':r'Input5flush$', 'absorb':r'Input6absorb$',
       'clear':r'Input5clear$', 'encoded_drop':r'SecretEncodedIntegerE'}
STATE='_RNvMs2_CscBEH4D3OuJh_22sha3_accelerated_stateNtB5_5State'
PANIC='_RNvNtNtCs8xEFJqa6dYS_4core9panicking11panic_const24panic_const_shr_overflow'
CLEAR={
    'scalar':'564883ec204889cee800000000c60600488d8e70040000ba10000000e800000000'
        '488d8e80040000ba10000000e800000000488d8e90040000ba10000000e800000000'
        '0f57c00f2986a00400004883c4205ec3',
    'avx2':'564883ec204889ce83b9b0030000ff74084889f1e80000000048c786b0030000ffffffff'
        '488d8ee0030000ba10000000e800000000488d8ef0030000ba10000000e800000000'
        '488d8e00040000ba10000000e800000000c5f857c0c5f81186180400004883c4205ec3',
}
ENCODED_DROP='564883ec204889ceba11000000e8000000004883c611ba010000004889f14883c4205ee900000000'
HANDLERS={
    'finish_drop':'48895424105541574156415541545657534883ec28488daa800000004889e9e800000000'
        '904883c4285b5f5e415c415d415e415f5dc3',
    'flush_drop':'48895424105541574156415541545657534883ec28488daa800000004883e2e04889d3'
        '488d8bc0000000ba40000000e800000000904883c4285b5f5e415c415d415e415f5dc3',
}


def names(functions,lane):
    result={role:s.one(functions,pattern) for role,pattern in ROLES.items()}
    if lane=='avx2':
        result.update(finish_drop='?dtor$32@?0?'+result['finish']+'@4HA',
                      flush_drop='?dtor$20@?0?'+result['flush']+'@4HA')
    require(set(result.values())<=set(functions),'actual selected leaf bodies/handlers')
    return result


def expected_calls(functions,lane):
    n=names(functions,lane);z=s.ZERO
    absorb=s.one(functions,r'Input6absorb$')
    state_drop=s.one(functions,r'drop_glue.*'+
        ('parallel_stream_state5StateE' if lane=='scalar' else 'sha3_accelerated_state5StateE'))
    mask=s.CORE+'13secret_memory24secret_byte_mask_is_zero'
    if lane=='scalar':
        update=s.one(functions,r'parallel_stream_state.*State6update$')
        calls={
            'finish':{0x66:absorb,0x13f:mask,0x194:n['flush'],0x1ea:'__udivti3',
                0x27c:z,0x28f:z,0x3bb:update,0x3c7:n['clear'],0x3cf:n['encoded_drop'],
                0x3e9:z,0x3f6:z,0x402:PANIC},
            'flush':{0xb6:s.one(functions,r'HardenedCshake12824enter_squeezing_in_place$'),
                0xd2:s.one(functions,r'State4leaf$'),0x102:'memcpy',0x10a:state_drop,
                0x123:'memcpy',0x143:s.one(functions,r'HardenedCshake25624enter_squeezing_in_place$'),
                0x19f:s.one(functions,r'parallel_stream_state.*State7squeeze$'),0x1b4:z,
                0x1f0:s.one(functions,r'HardenedFips202OwnerKja8_E6update'),
                0x20f:s.one(functions,r'HardenedFips202OwnerKj88_E6update'),
                0x229:state_drop,0x239:z,0x256:z},
            'clear':{0x9:state_drop,0x1d:z,0x2e:z,0x3f:z}}
        calls['absorb']={0x8b:s.one(functions,r'State4leaf$'),0xb7:'memcpy',
            0xbf:state_drop,0xdd:'memcpy',
            0x140:s.one(functions,r'HardenedFips202OwnerKja8_E6update'),
            0x167:s.one(functions,r'HardenedFips202OwnerKj88_E6update'),0x1b3:n['flush']}
    else:
        calls={
            'finish':{0x76:absorb,0x13f:mask,0x18f:n['flush'],0x1df:'__udivti3',
                0x268:z,0x27b:z,0x3a3:STATE+'6update',0x3b2:n['clear'],
                0x3bb:n['encoded_drop'],0x3d5:z,0x3e2:z,0x3ee:PANIC},
            'flush':{0xce:STATE+'10finish_xof',0x134:STATE+'7squeeze',0x154:z,
                0x191:STATE+'7initial',0x1d3:'memcpy',0x209:'memcpy',0x238:state_drop,
                0x25a:'memcpy',0x2a4:STATE+'6update',0x2cb:state_drop,0x2e9:z,0x308:z},
            'clear':{0x15:state_drop,0x31:z,0x42:z,0x53:z},
            'finish_drop':{0x20:n['encoded_drop']},'flush_drop':{0x30:z}}
        calls['absorb']={0xca:STATE+'7initial',0x10b:'memcpy',0x149:'memcpy',
            0x17d:state_drop,0x1a4:'memcpy',0x231:STATE+'6update',0x27e:n['flush']}
    calls['encoded_drop']={0xe:z,0x24:z}
    return calls


def calls_check(bodies,refs,expected):
    require(set(bodies)==set(refs)==set(expected),'selected leaf call population')
    for role,targets in expected.items():
        actual=refs[role]
        require(len(actual)==len(targets) and {r['offset']:r['symbol'] for r in actual}==targets,
            'every leaf relocation has its actual semantic target')
        for r in actual:
            at=r['offset'];op=b'\xe9' if role=='encoded_drop' and at==0x24 else b'\xe8'
            require(r['trailing']==r['addend']==0 and bodies[role][at-1:at+4]==op+bytes(4),
                'leaf call/tail operand without hidden addend')


def instructions(bodies,refs,expected,lane):
    calls_check(bodies,refs,expected)
    finish.windows(bodies['finish'],finish.ANCHORS[lane],finish.BRANCHES[lane])
    cv=flush.check(bodies['flush'],lane)
    require(bodies['clear']==bytes.fromhex(CLEAR[lane]),'full typed Input cleanup body')
    require(bodies['encoded_drop']==bytes.fromhex(ENCODED_DROP),'full 17+1-byte suffix cleanup')
    if lane=='avx2':
        for role,code in HANDLERS.items():
            require(bodies[role]==bytes.fromhex(code),'actual invoked handler cleanup body')
    return dict(absorb=absorb.check(bodies['absorb'],lane),
        leaf_completion=dict(checked_total_bits=True,divisor_bits=67,
        exact_pending_and_leaf_count=True,suffix='right_encode(exact leaves)',
        suffix_bytes_maximum=17,secret_suffix_allocation_bytes=18,
        builtin_division_contract='package 8',model_is_machine_execution=False),
        cv=cv,input_clear=dict(used_leaves_bits_bytes=[16,16,16],
        active_leaf_drop_before_disarm=True,authority_pointer_retained=(lane=='avx2'),
        inactive_variant_padding_erased_here=False),
        invoked_handlers_only=(lane=='avx2'),arbitrary_exception_guarantee=False)


def inspect_route(base,root,lane,pin,mutate):
    inputs,sources=inventory.load(base,root,pin)
    functions=c.previous.inventory(inputs['object']);inventory.functions_check(functions,pin)
    records=c.previous.bind_all(inputs['object'],inputs['image'],functions)
    selected=names(functions,lane)
    bodies={role:functions[name][0] for role,name in selected.items()}
    refs={role:functions[name][1] for role,name in selected.items()}
    semantics=instructions(bodies,refs,expected_calls(functions,lane),lane)
    if lane=='avx2':
        for parent,handler in (('finish','finish_drop'),('flush','flush_drop')):
            require(any(m['symbol']==selected[handler] and
                m['target_rva']==records[selected[handler]]['rva']
                for m in records[selected[parent]].get('metadata',[])),
                'actual parent xdata names bound handler, not listing alias')
    mutations=0
    if mutate:
        for role,name in selected.items():
            code,relocations,kind=functions[name]
            for at in range(len(code)):
                bad=bytearray(code);bad[at]^=1
                try:c.body_check((bad,relocations,kind),pin['functions'][name])
                except ValueError:mutations+=1
                else:raise AssertionError('accepted selected body mutation')
    return dict(object_sha256=digest(inputs['object']),image_sha256=digest(inputs['image']),
        source_sha256=sources,entries={role:records[name] for role,name in selected.items()},
        semantics=semantics,body_byte_mutations_rejected=mutations,
        assembly_listing_used_for_semantics=False,
        complete_sequential_path=False,remaining=['state/owner caller composition',
            'customization/rehash and final output framing',
            'original allocations, failure paths and full resident retirement'])


def inspect(base,root,mutate=False):
    spec=inventory.specification(inventory.SPEC.read_bytes())
    routes={lane:inspect_route(base,root,lane,spec[lane],mutate) for lane in ('scalar','avx2')}
    return dict(schema=1,status='AUTHOR_SELECTED_PARALLELHASH_LEAF_COMPLETION',routes=routes,
        completion_package=7,pass_number=2,pass_complete=False,completion_package_closed=False,
        whole_image_qualified=False,independently_verified=False,new_native_run=False,
        release_gate_changed=False,shared_runtime_window_package=8,
        source_sha256={p.name:digest(p.read_bytes()) for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')} | {Path(__file__)})})


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path)
    p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path)
    args=p.parse_args();result=inspect(args.saved_directory,args.source_root,args.mutate)
    text=json.dumps(result,indent=2)+'\n'
    if args.output:args.output.write_text(text,encoding='utf-8')
    else:print(text,end='')
