"""Saved TupleHash chain review; author evidence, never a release gate."""
import argparse
import json
from pathlib import Path
import re
import sys

import windows_enclave_kmac_chains as c
import windows_enclave_tuple_reuse as reuse
import windows_enclave_tuple_shapes as shapes
import windows_enclave_tuple_lifecycle as lifecycle

SPEC=c.shared.CATALOG.with_name('tuple-chains-20261006.json')
SPEC_HASH='8365f34e0f00fd7e8563341bd18a8f6680c096d64a60fb5fe2e679f94dcfe615'
RUNTIME={'memcpy','memset','memcmp','__chkstk','__umodti3','PublicProbeAbort',
         'PublicTupleInput','PublicTupleOutput','PublicTupleSource','PublicTupleObserve'}
require,digest=c.require,c.digest


def specification(raw):
    require(digest(raw)==SPEC_HASH,'frozen TupleHash scalar/AVX2 inventory')
    result=json.loads(raw)
    require(set(result)=={'scalar','avx2'},'both TupleHash routes')
    require([len(result[k]['functions']) for k in ('scalar','avx2')]==[52,61],'complete saved populations')
    return result


def inspect_route(base,root,lane,pin,mutate,prior):
    row,data,image,asm,ir,sources=c.load(base,root,lane,pin,'tuple-worker-build.json')
    functions=c.previous.inventory(data)
    require(set(functions)==set(pin['functions']),'complete frozen function population')
    for name,values in functions.items(): c.body_check(values,pin['functions'][name])
    assembly=c.previous.s.bodies(asm,functions)
    semantics=shapes.inspect(assembly,lane)
    semantics.update(lifecycle.inspect(assembly,lane))
    reused=reuse.inspect(base,root,lane,functions,ir,assembly,prior)
    records=c.previous.bind_all(data,image,functions)
    constants,tables,runtime=c.data_bindings(data,image,records,functions,RUNTIME)
    kernel=permutation(data,image,asm,assembly,records,lane)
    transport=c.transport_binding(base,row,data,image,records,runtime,'PublicTuple')
    sizes,edges,vectors,indirect,geometry=c.frames(records,assembly)
    require(set(indirect)==set(tables),'all TupleHash indirect targets assigned')
    require(all(len(indirect[n])==len(t['operands']) for n,t in tables.items()),'complete dispatch operands')
    reached=set()
    def visit(name):
        if name in reached: return
        reached.add(name)
        for child in edges[name]: visit(child)
    visit('RetainedWork');normal=len(reached)
    for name in list(reached):
        for m in records[name].get('metadata',[]):
            if m['symbol'] in records: visit(m['symbol'])
    require(reached==set(records),'no orphan emitted TupleHash body')
    count=table_count=0
    if mutate:
        for name,(code,refs,kind) in functions.items():
            for at in range(len(code)):
                bad=bytearray(code);bad[at]^=1
                try: c.body_check((bad,refs,kind),pin['functions'][name])
                except ValueError: count+=1
                else: raise AssertionError('accepted body mutant')
        for name,p in tables.items():
            raw=bytes.fromhex(p['linked_hex'])
            for at in range(len(raw)):
                bad=bytearray(raw);bad[at]^=1
                try: c.previous.s.scalar.ops.table_destinations(bad,p['rva'],records[name]['rva'],p)
                except ValueError: table_count+=1
                else: raise AssertionError('accepted dispatch mutant')
    return dict(route=row['route'],source_sha256=sources,image_sha256=digest(image),
        object_sha256=digest(data),body_byte_mutations_rejected=count,table_byte_mutations_rejected=table_count,
        normal_reachable_functions=normal,total_functions=len(records),
        cleanup_funclets=sum(n.startswith('?') for n in records),kernel=kernel,transport=transport,
        constants=constants,dispatch_tables=tables,geometry=geometry,
        functions={n:dict(rva=r['rva'],bytes=r['size'],frame_bytes=sizes[n],saved_vectors=vectors[n],
            inner_calls=edges[n],references=r['reference_targets']) for n,r in sorted(records.items())},
        semantics=semantics,helper_reuse=reused,runtime_boundaries_pending=runtime,whole_image_qualified=False)


def scalar_labels(body):
    # Exact saved compilation-local renumbering, not removal of branch targets.
    mapping={'.Ltmp'+str(n):'.Ltmp'+str(n-4) for n in range(8,14)}
    labels=re.findall(r'(?m)^\s*(\.Ltmp\d+):',body)
    require(labels==list(mapping),'six distinct scalar loop labels in reviewed order')
    require(set(re.findall(r'\.Ltmp\d+',body))==set(mapping),'no unassigned local target')
    return re.sub(r'\.Ltmp\d+',lambda m:mapping[m[0]],body)


def permutation(data,image,asm,assembly,records,lane):
    if lane=='scalar':
        name=c.previous.s.scalar.PERMUTE
        start=asm.index('\n'+name+':\n');end=asm.index('.seh_endproc',start)
        asm=asm[:start]+scalar_labels(asm[start:end])+asm[end:]
    return c.permutation(data,image,asm,assembly,records,lane)


def inspect(base,root,mutate=False):
    spec=specification(SPEC.read_bytes())
    prior=c.inspect(base,root)
    routes={lane:inspect_route(base,root,lane,pin,mutate,prior['routes'][lane]) for lane,pin in spec.items()}
    return dict(schema=1,status='AUTHOR_PARTIAL_TUPLEHASH_CHAIN_REVIEW',routes=routes,
        completion_package=4,completion_package_closed=False,whole_image_qualified=False,
        independent_retest=False,release_gate_changed=False,native_run_added=False,
        remaining_private_review=['constructor and customization transfers',
            'retained rehash and output export composition',
            'state finalizer and reader composition', 'six AVX2 cleanup funclets',
            'worker/page retirement and frame storage assignments',
            'scalar fail-stop panic path preconditions'],
        source_sha256={p.name:digest(p.read_bytes()) for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')} | {Path(__file__)})})


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path)
    p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path)
    args=p.parse_args();result=inspect(args.saved_directory,args.source_root,args.mutate)
    text=json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
