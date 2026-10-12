"""Byte-bound resident canary compute/retirement review, not SDK qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

import windows_enclave_isolated_review as original
import windows_enclave_stack_bridge as bridge
from windows_enclave_bounded_callbacks import exported

review,workers,require = original.review,original.workers,original.require
digest = lambda raw: hashlib.sha256(raw).hexdigest()
PINS = {
    'PublicIsolatedSha256': ('48c9d32e71c32c896a58f889e5100d7e9d0b11a5acdc86e4d1c2d1ed6dea1253',
        '090c0e2b6f913812445730eeef3e254143316ea21e882eb318678d486227b17a'),
    'PublicRustBody': ('64b3111d351b29ab242f0b10a93902cf17b41cbf3aebafc032a62098182e307b',
        'e3c0bee19b3dff6653a621967ba5641b5af358cdb3be35bb55a548b455d91d0b'),
    'stage_notify': ('56a6e5a56a1ab1ff8b0592f0490a828adc246a14713a9d93b0476c63b418b1b4',
        '05c86090198c0d50bdf1e8b98310b9aef13790298b2a4a6b6244401d4a2f2484'),
}
RETIRE = bytes.fromhex('33c0ba0010000048894411f84883ea0875f54533c0ba00100000'
    '4c0b4411f84883ea0875f54d85c0751333c033c933d24533c04533c94533d24533dbc3'
    'b907000000cd29ebf7')


def bind(obj,image,name,rva):
    raw,refs,targets = bridge.bind(obj,image,name,rva)
    require((digest(raw),digest(json.dumps(refs,sort_keys=True).encode())) == PINS[name],
            'reviewed complete body and relocation identity '+name)
    return raw,refs,dict(rva=rva,size=len(raw),reference_targets=targets)


def retire(obj,image,rva):
    raw,refs,targets = bridge.bind(obj,image,'IsolatedRetirePage',rva)
    require(raw == RETIRE and not refs and not targets,'exact complete retirement leaf')
    # Both loops start at 4096, touch [RCX+RDX-8, +8), decrement by eight and
    # test the decrement's flags. No stack access/call or vector instruction.
    offsets = list(range(4096-8,-1,-8))
    require(len(offsets)==512 and sorted(b for o in offsets for b in range(o,o+8))==list(range(4096)),
            'exact once-only full-page store/readback coverage')
    return dict(rva=rva,bytes=len(raw),sha256=digest(raw),page_bytes=4096,
        stores=512,readbacks=512,stack_bytes=0,sdk_calls=0,
        normal_return_requires_zero_readback=True,dirty_readback='fatal int29, not cleanup success',
        modified_gprs_cleared_on_return=['rax','rcx','rdx','r8','r9','r10','r11'],
        caller_register_context_qualified=False)


def control_flow(code):
    """Complete direct CFG, with int29 terminal rather than a normal edge."""
    edges = {}
    for at,(raw,text) in code.items():
        op = text.split(' ',1)[0]
        after = at+len(raw)
        if raw == b'\xcd\x29' or op == 'retq': edges[at]=[]
        elif op.startswith('j'):
            target = review.decode.relative(raw,at)
            edges[at] = [target] if op in ('jmp','jmpq') else [target,after]
        else: edges[at]=[after]
        require(all(v in code for v in edges[at]),'complete local lifecycle CFG')
    reached,pending = set(),[0]
    while pending:
        at = pending.pop()
        if at not in reached:
            reached.add(at)
            pending.extend(edges[at])
    require(reached == set(code),'no omitted/unreachable instruction in reviewed root')
    parents = {at:{p for p in edges if at in edges[p]} for at in edges}
    dom = {at:({0} if at==0 else set(edges)) for at in edges}
    changed = True
    while changed:
        changed = False
        for at in sorted(edges):
            if at==0: continue
            value = {at}|set.intersection(*(dom[p] for p in parents[at]))
            if value != dom[at]: dom[at]=value;changed=True
    return dom


def lifecycle(image,record,raw,refs,text):
    code = review.decode.body(image,record,review.decode.parse(text))
    dom = control_flow(code)
    selected = {}
    for ref in refs:
        at = ref['offset']-(2 if ref['symbol'].startswith('__imp_') else 1)
        if at in code and code[at][1].startswith('callq '):
            selected.setdefault(ref['symbol'],[]).append(at)
    require(selected['EnclaveCopyIntoEnclave']==[175,534] and
        selected['stage_notify']==[482,558,746] and selected['PublicLockedWindow']==[576] and
        selected['EnclaveCopyOutOfEnclave']==[638] and selected['IsolatedRetirePage']==[717] and
        selected['__imp_VirtualFree']==[789],'exact descriptor/input/admit/observe/compute/retire sites')
    # Dominance does not infer API success. The pinned conditional branches and
    # native denied/failing operations are separately reviewed/tested.
    relations = [(482,534),(482,558),(558,576),(576,638),(717,746),(717,789)]
    for first,second in relations:
        require(first in dom[second],'mandatory lifecycle predecessor')
    return dict(body_sha256=digest(raw),rva=record['rva'],bytes=len(raw),
        direct_and_import_call_sites=selected,dominance_pairs=relations,
        status_checks_bound_by_complete_body_pin=True,sdk_effects_qualified=False)


def inspect(directory,text):
    image = (directory/'signed.dll').read_bytes()
    obj = (directory/'normal.obj').read_bytes()
    raw,refs,root = bind(obj,image,'PublicIsolatedSha256',exported(image,'PublicIsolatedSha256'))
    roots = root['reference_targets']
    phases = lifecycle(image,root,raw,refs,text)
    retirement = retire((directory/'retire.obj').read_bytes(),image,roots['IsolatedRetirePage'])
    _,_,notify = bind(obj,image,'stage_notify',roots['stage_notify'])
    require(notify['reference_targets']['stage_region']==roots['stage_region'] and
        notify['reference_targets']['host_callback']==roots['host_callback'],'same staging/host identity')
    imports = bridge.sdk.imports(image)['vertdll.dll']
    require(notify['reference_targets']['__imp_CallEnclave']==imports['CallEnclave'], 'actual callback IAT')
    for name in ('VirtualAlloc','VirtualProtect','VirtualFree'):
        require(roots['__imp_'+name]==imports[name],'actual named storage import')
    rows,unwind = bridge.caller.pe.linked(image)
    for name in ('EnclaveCopyIntoEnclave','EnclaveCopyOutOfEnclave'):
        bridge.sdk.thunk(rows,unwind,roots[name],imports[name])
    members = workers.chain.w.archive.members((directory/'normal_rust.lib').read_bytes())
    selected = [(n,d) for n,d in members.items() if n.startswith('isolated_sha256.')]
    require(len(selected)==1,'one Rust canary object')
    member,data = selected[0]
    functions,records = workers.bind(data,image)
    require(len(functions)==7 and 'IsolatedSha256' in functions,'seven complete Rust functions')
    wrapper = workers.catalog.sdk.pe.bind((directory/'window.obj').read_bytes(),image,'PublicLockedFrame')
    raw,refs,adapter = bind(obj,image,'PublicRustBody',wrapper['call_target_rvas']['PublicRustBody'])
    require(adapter['reference_targets']['IsolatedSha256']==records['IsolatedSha256']['rva'],
            'actual compute tail connection')
    for name in ('busy','active','admitted','stage_admitted','stage_region','body_calls','request'):
        require(adapter['reference_targets'][name]==roots[name],'same phase/storage identity '+name)
    functions['PublicRustBody']=(raw,refs,False)
    records['PublicRustBody']=adapter
    memory = workers.catalog.memory.inspect(image,records['IsolatedSha256']['reference_targets']['memset'])
    runtime = {name:dict(rva=memory['frames'][role]['rva'],bytes=memory['frames'][rep]['fixed_frame_bytes'])
        for name,role,rep in [('memcpy','copy','copy_rep'),('memset','fill','fill_rep')]}
    instructions,nodes = review.decode.parse(text),{}
    for name,(_,refs,_) in functions.items():
        decoded = review.decode.body(image,records[name],instructions)
        tables = [] if name=='PublicRustBody' else review.decode.destinations(data,image,name,records[name],refs)
        nodes[name]=dict(incoming_bytes=32,scans=review.flow.inspect(decoded,records[name]['rva'],tables,set()))
    population = review.assign(functions,records,nodes,runtime,None)
    closure = original.compute_closure(nodes,['PublicRustBody'])
    bound = review.composition.compose(nodes)['PublicRustBody']
    require(all(v['finite_transitive_bound_proven'] and v['complete_stack_bytes']==2544
                for v in bound.values()),'unchanged bounded compute under both entry residues')
    build = json.loads((directory/'build.json').read_text())
    require(build['dirty_staging_mutant'] is False,'not the omitted-clear negative image')
    root_path = Path(__file__).resolve().parents[2]
    for name,expected in build['source_sha256'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts,'relative build source')
        require(digest((root_path/name).read_bytes())==expected,'current canary source '+name)
    return dict(schema=1,status='AUTHOR_RESIDENT_COMPUTE_AND_RETIREMENT_PREFIX',
        image_sha256=digest(image),object_member=member,disassembly_sha256=digest(text.encode()),
        **population,closure=closure,normal_compute_bound=bound,lifecycle=phases,retirement=retirement,
        root_binding=root,entry_adapter=adapter,wrapper_binding=wrapper,memory_runtime=memory,
        transport_payload_handling_qualified=False,complete_wrapper_cleanup_requalified=False,
        staging_residency_qualified=False,whole_image_qualified=False,completion_package_closed=False,
        production_qualified=False,source_sha256={p.name:digest(p.read_bytes()) for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
            | {Path(__file__)})})


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--disassembly',type=Path)
    args = parser.parse_args()
    text = args.disassembly.read_text() if args.disassembly else review.decode.disassemble(args.directory/'signed.dll')
    print(json.dumps(inspect(args.directory,text),indent=2))
