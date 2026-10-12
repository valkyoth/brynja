"""Actual 08A canary compute graph; excludes transport/storage qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

import windows_enclave_stack_review as review
from windows_enclave_isolation_design import compute_closure

workers = review.workers
require = workers.require
BODY = bytes.fromhex('833d000000000074378b050000000085c0742d488b05000000004885c07421'
    '48ff05000000004c8d0500000000488b1508000000488d0d00000000e90000000033c0c3')
REFS = [(2,'busy',1,0), (11,'active',0,0), (22,'admitted',0,0),
        (34,'body_calls',0,0), (41,'output_stage',0,0), (48,'request',0,8),
        (55,'input_stage',0,0), (60,'IsolatedSha256',0,0)]


def cbody(obj, image, wrapper, rust):
    caller = workers.chain.shared.caller
    code, refs = caller.function(obj, 'PublicRustBody')
    require(code == BODY and [(r['offset'],r['symbol'],r['trailing'],r['addend'])
            for r in refs] == REFS, 'exact checked phase tests and tail adapter')
    rva = wrapper['call_target_rvas']['PublicRustBody']
    rows, functions = caller.pe.linked(image)
    linked = bytearray(workers.catalog.sdk.mapped(rows, rva, len(code)))
    targets = {}
    for ref in refs:
        at = ref['offset']
        targets[ref['symbol']] = rva+at+4+ref['trailing']+int.from_bytes(
            linked[at:at+4], 'little', signed=True)-ref['addend']
        linked[at:at+4] = code[at:at+4]
    require(bytes(linked) == code and targets['IsolatedSha256'] == rust['rva'],
            'actual wrapper to C to Rust tail connection')
    require(not any(a < rva+len(code) and rva < b for a,b,_ in functions),
            'leaf adapter has no conflicting runtime extent')
    sizes = dict(busy=4,active=4,admitted=8,body_calls=8,output_stage=32,request=32,input_stage=1024)
    spans = []
    for name, size in sizes.items():
        address = targets[name]
        require(any(row['flags'] & 0xe0000000 == 0xc0000000 and row['rva'] <= address
            and address+size <= row['rva']+row['virtual_size'] for row in rows),
            'complete enclave-owned nonexecutable staging/control object')
        spans.append((address,address+size))
    spans.sort()
    require(all(a[1] <= b[0] for a,b in zip(spans,spans[1:])), 'distinct full staging/control ranges')
    return code,refs,dict(rva=rva,size=len(code),reference_targets=targets)


def inspect(directory, text):
    image = (directory/'signed.dll').read_bytes()
    members = workers.chain.w.archive.members((directory/'normal_rust.lib').read_bytes())
    selected = [(n,d) for n,d in members.items() if n.startswith('isolated_sha256.')]
    require(len(selected) == 1, 'one complete canary Rust object')
    member,data = selected[0]
    functions,records = workers.bind(data,image)
    require(len(functions) == 7 and 'IsolatedSha256' in functions, 'reviewed seven-body Rust population')
    wrapper = workers.catalog.sdk.pe.bind((directory/'window.obj').read_bytes(),image,'PublicLockedFrame')
    code,refs,record = cbody((directory/'normal.obj').read_bytes(),image,wrapper,records['IsolatedSha256'])
    functions['PublicRustBody'] = (code,refs,False)
    records['PublicRustBody'] = record
    memory = workers.catalog.memory.inspect(image,records['IsolatedSha256']['reference_targets']['memset'])
    runtime = {name:dict(rva=memory['frames'][role]['rva'],bytes=memory['frames'][rep]['fixed_frame_bytes'])
        for name,role,rep in [('memcpy','copy','copy_rep'),('memset','fill','fill_rep')]}
    instructions = review.decode.parse(text)
    nodes = {}
    for name,(_,refs,_) in functions.items():
        decoded = review.decode.body(image,records[name],instructions)
        tables = [] if name == 'PublicRustBody' else review.decode.destinations(data,image,name,records[name],refs)
        nodes[name] = dict(incoming_bytes=32,scans=review.flow.inspect(decoded,records[name]['rva'],tables,set()))
    population = review.assign(functions,records,nodes,runtime,None)
    closure = compute_closure(nodes,['PublicRustBody'])
    bound = review.composition.compose(nodes)['PublicRustBody']
    require(all(v['finite_transitive_bound_proven'] and v['complete_stack_bytes'] == 2544
                for v in bound.values()), 'exact finite normal compute bound at both residues')
    build = json.loads((directory/'build.json').read_text())
    root = Path(__file__).resolve().parents[2]
    for path,sha in build['source_sha256'].items():
        require(not Path(path).is_absolute() and '..' not in Path(path).parts,
                'relative build input')
        require(hashlib.sha256((root/path).read_bytes()).hexdigest() == sha,'current canary build input '+path)
    return dict(schema=1,status='AUTHOR_CANARY_NORMAL_COMPUTE_GRAPH',
        image_sha256=hashlib.sha256(image).hexdigest(),object_member=member,
        object_sha256=hashlib.sha256(data).hexdigest(),
        disassembly_sha256=hashlib.sha256(text.encode()).hexdigest(),
        **population,closure=closure,normal_compute_bound=bound,
        entry_adapter=record,wrapper_binding=wrapper,memory_runtime=memory,
        function_geometry=nodes,production_qualified=False,completion_package_closed=False,
        transport_payload_handling_qualified=False,staging_residency_qualified=False,
        complete_wrapper_cleanup_requalified=False,
        source_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
            | {Path(__file__)})})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--disassembly', type=Path)
    args = parser.parse_args()
    text = args.disassembly.read_text() if args.disassembly else review.decode.disassemble(args.directory/'signed.dll')
    print(json.dumps(inspect(args.directory,text),indent=2))
