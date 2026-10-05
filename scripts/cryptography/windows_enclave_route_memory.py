"""Rebind reviewed memory-runtime bodies to saved sequential worker images.

This is offline author-review support. It does not infer caller argument safety,
live selector values, indirect-call closure or whole-image qualification.
"""
import argparse
import json
from pathlib import Path
import struct

import windows_enclave_bounded_memory as bounded

prior,shared = bounded.prior,bounded.shared
require,digest = shared.require,shared.digest
SELECTORS = {0x11060:4,0x11068:8,0x11070:8,0x118bc:1}


def normalize(bodies,delta):
    require(type(delta) is int and set(bodies) == set(prior.BODIES),'complete runtime population and shift')
    copies = {n:bytearray(b) for n,b in bodies.items()};targets = {};tables = {}
    for n,(_,size,_) in prior.BODIES.items(): require(len(bodies[n]) == size,'complete runtime body')
    for n,address,prefix,target,suffix in prior.RIP_READS:
        at = address-prior.BODIES[n][0];p,s = bytes.fromhex(prefix),bytes.fromhex(suffix)
        operand = at+len(p);end = operand+4+len(s)
        require(bodies[n][at:operand] == p and bodies[n][operand+4:end] == s,'exact RIP instruction')
        actual = prior.BODIES[n][0]+delta+end+int.from_bytes(bodies[n][operand:operand+4],'little',signed=True)
        require(target not in targets or targets[target] == actual,'consistent selector identity')
        require(actual >= 0 and (target != 0 or actual == 0),'image-base identity')
        targets[target] = actual
        copies[n][operand:operand+4] = (target-prior.BODIES[n][0]-end).to_bytes(4,'little',signed=True)
    for n,address,table,small in prior.DISPATCH:
        at = address-prior.BODIES[n][0]
        p = bytes.fromhex('478b8c82' if small else '478b9c9a')
        s = bytes.fromhex('4d03ca41ffe1' if small else '4d03da41ffe3')
        require(bodies[n][at:at+4] == p and bodies[n][at+8:at+14] == s,'exact table dispatch instruction')
        tables[table] = int.from_bytes(bodies[n][at+4:at+8],'little')
        copies[n][at+4:at+8] = struct.pack('<I',table)
    normalized = {n:bytes(b) for n,b in copies.items()}
    prior.check_bodies(normalized);prior.check_instructions(normalized)
    require(set(targets) == {0,*SELECTORS} and set(tables) == set(prior.TABLES),'complete runtime references')
    return normalized,targets,tables


def mapped_tables(rows,table_addresses,delta):
    require(set(table_addresses) == set(prior.TABLES),'all eight dispatch tables')
    result = {}
    for old,targets in prior.TABLES.items():
        address = table_addresses[old];values = tuple(t+delta for t in targets)
        require(all(0 <= t < 1<<32 for t in values),'bounded table destinations')
        prior.session.setup.construction.constant(rows,address,struct.pack('<16I',*values))
        result[hex(address)] = dict(previous_rva=old,targets=values)
    require(len(result) == 8,'distinct dispatch table regions')
    return result


def selectors(rows,targets):
    spans = []
    for old,size in SELECTORS.items():
        address = targets[old]
        owners = [r for r in rows if r['rva'] < address+size and address < r['rva']+r['virtual_size']]
        require(len(owners) == 1 and owners[0]['rva'] <= address and
                address+size <= owners[0]['rva']+owners[0]['virtual_size'] and
                owners[0]['flags'] & 0xe0000000 == 0xc0000000,'bounded writable nonexecutable selector')
        spans.append(dict(rva=address,bytes=size,live_value_established=False))
    ordered = sorted(spans,key=lambda s:s['rva'])
    require(all(a['rva']+a['bytes'] <= b['rva'] for a,b in zip(ordered,ordered[1:])),'separate selector storage')
    return spans


def inspect(image,fill_rva,mutate=False):
    require(type(fill_rva) is int and 0 < fill_rva < 1<<32,'incoming memset address')
    delta = fill_rva-prior.BODIES['fill'][0];rows,functions = shared.caller.pe.linked(image)
    bodies = {n:prior.session.executable(rows,a+delta,size) for n,(a,size,_) in prior.BODIES.items()}
    _,targets,addresses = normalize(bodies,delta)
    tables = mapped_tables(rows,addresses,delta);frames = {}
    for n,(old,size,_) in prior.BODIES.items():
        start = old+delta
        found = [f for f in functions if f[0] < start+size and start < f[1]]
        require(len(found) == 1 and found[0][:2] == (start,start+size),'complete runtime extent')
        _,raw,stack = prior.UNWIND[n]
        prior.session.setup.construction.constant(rows,found[0][2],bytes.fromhex(raw))
        frames[n] = dict(rva=start,bytes=size,unwind_rva=found[0][2],unwind_hex=raw,
                         fixed_frame_bytes=stack,unwind_semantics_qualified=False)
    count = 0
    if mutate:
        for name,body in bodies.items():
            for i in range(len(body)):
                changed = bytearray(body);changed[i] ^= 1
                try:
                    _,bad_targets,bad_tables = normalize(bodies | {name:bytes(changed)},delta)
                    require(bad_targets == targets and bad_tables == addresses,'same runtime destinations')
                except ValueError: count += 1
                else: raise AssertionError('accepted actual runtime byte mutation')
    return dict(image_sha256=digest(image),frames=frames,tables=tables,selectors=selectors(rows,targets),
                body_sha256={n:digest(b) for n,b in bodies.items()},actual_body_byte_mutations_rejected=count,
                runtime_normal_paths_reused=True,caller_argument_safety_inferred=False,
                live_dispatch_values_qualified=False,arbitrary_exception_cleanup_qualified=False,
                maximum_transitive_depth_qualified=False,whole_image_qualified=False)


def collect(base,catalog,mutate=False):
    # Find the exact reviewed REP fill prefix, then check the entire adjacent
    # runtime population. Caller edges remain a separate required check.
    result = []
    for row in shared.catalog(catalog):
        image = (base/row['image']).read_bytes()
        require(digest(image) == row['sha256'],'saved route image identity')
        rows,_ = shared.caller.pe.linked(image)
        prefix = bytes.fromhex(next(h for n,_,h in prior.ANCHORS if n == 'fill_rep'))
        candidates = []
        for section in rows:
            if section['flags'] & 0xe0000000 != 0x60000000: continue
            at = section['code'].find(prefix)
            while at != -1:
                candidates.append(section['rva']+at+16)
                at = section['code'].find(prefix,at+1)
        require(len(candidates) == 1,'one complete REP fill prefix')
        fill = candidates[0]
        result.append(dict(route=row['route'],**inspect(image,fill,mutate)))
    return dict(schema=1,date='2026-10-05',status='SAVED_ROUTE_MEMORY_REBINDING',records=result,
                independent_review=False,native_run_added=False,release_gate_changed=False,
                worker_semantics_inferred=False,whole_image_qualified=False)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path)
    p.add_argument('--catalog',type=Path,default=shared.CATALOG)
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path)
    args = p.parse_args();result = collect(args.saved_directory,args.catalog.read_bytes(),args.mutate)
    result['source_sha256'] = {n:digest(Path(__file__).with_name(n).read_bytes()) for n in
        ('windows_enclave_route_memory.py','windows_enclave_memory_runtime.py','test-windows-enclave-route-memory.py')}
    text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
