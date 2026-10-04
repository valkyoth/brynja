"""Selected saved unwinder frames, not unwind correctness or cleanup proof."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_sdk_locking as locking
from windows_enclave_frame_geometry import Frame, Window

diagnostic = locking.diagnostic
require = locking.require
BODIES = {
    'engine': (0xcf78,2281,'cd977cc7c29997eca97e1c6c969c36dba96def64d2ec2ec3cb9b1da9e5b15fe4'),
    'chain_entry': (0xc4e8,72,'fa605d58409ea8288f78868b98fdd3eb627eb014092afb7e845aac22bfe2d9f5'),
    'code_slots': (0xc904,64,'0f9ec12dccbccc31b27524f5a399ba3b1605ef562262546172fd95d805f8fd49'),
}
EDGES = (
    ('engine',0xd0e1,0xbeb0), ('engine',0xd13a,0xc904),
    ('engine',0xd365,0xc4e8), ('engine',0xd378,0x8b60),
    ('engine',0xd38a,0xc4e8), ('engine',0xd754,0xc538),
    ('engine',0xd7a6,0xc94c), ('chain_entry',0xc522,0xbeb0),
    ('code_slots',0xc920,0xbeb0),
)
TABLE_RVA = 0x23d10
TABLE = bytes.fromhex('0102010102030203020301')


def check_bodies(bodies):
    require(set(bodies) == set(BODIES),'complete unwind body population')
    for name,(_,size,digest) in BODIES.items():
        require(len(bodies[name]) == size and hashlib.sha256(bodies[name]).hexdigest() == digest,
                'unwind body: '+name)


def check_edges(bodies):
    for name,instruction,target in EDGES:
        require(diagnostic.status.relative_target(BODIES[name][0],bodies[name],
            instruction-BODIES[name][0],0xe8) == target,'unwind call: '+name)
    offset = 0xc926-BODIES['code_slots'][0]
    reference = bodies['code_slots'][offset:offset+7]
    require(len(reference) == 7 and reference[:3] == b'\x48\x8d\x0d' and
            0xc92d+int.from_bytes(reference[3:],'little',signed=True) == TABLE_RVA,
            'unwind slot table reference')


def check_table(table):
    require(table == TABLE,'exact eleven-entry unwind slot table')


def mutations(bodies,table):
    check_bodies(bodies)
    check_table(table)
    count = 0
    for name,body in bodies.items():
        for index in range(len(body)):
            changed = bytearray(body)
            changed[index] ^= 1
            try:
                check_bodies(bodies | {name:bytes(changed)})
            except ValueError:
                count += 1
            else:
                raise AssertionError('accepted unwind body mutation')
    for index in range(len(table)):
        changed = bytearray(table)
        changed[index] ^= 1
        try:
            check_table(bytes(changed))
        except ValueError:
            continue
        raise AssertionError('accepted unwind table mutation')
    return dict(body_bytes=count,table_bytes=len(table))


def geometry(window,capacity):
    result = {}
    runtime = locking.directory.runtime
    for path,origins in runtime.geometry(window,capacity).items():
        result[path] = {}
        for origin,row in origins.items():
            adapter = window.high+row['frames']['unwind']
            engine = Frame.enter(window,adapter,168)
            slots = Frame.enter(window,engine.current,40)
            chain = Frame.enter(window,engine.current,40)
            lookup = Frame.enter(window,engine.current,72)
            direct_raise = Frame.enter(window,engine.current,1432)
            helper_raise = Frame.enter(window,chain.current,1432)
            spans = [
                engine.slot('engine three argument home saves',16,24,'entry'),
                engine.slot('engine mode in first home slot',8,4,'entry'),
                engine.slot('engine six register pushes',-48,48,'entry'),
                engine.slot('engine outgoing stack arguments',32,32),
                engine.slot('engine staged pointers and decode locals',64,48),
                # This is adapter.current+80, NOT part of engine allocation.
                engine.slot('engine working flag in adapter slot',256,4),
                slots.slot('code-slot input home',8,2,'entry'),
                engine.slot('nested lookup image-base destination',88,8),
                window.span('adapter returned handler and address slots',adapter+96,16),
            ]
            result[path][origin] = dict(frames={n:f.current-window.high for n,f in
                (('engine',engine),('code_slots',slots),('chain_entry',chain),('lookup',lookup))},
                spans=spans,unknown_callees=[
                    engine.unknown_callee('epilogue interpreter entry 0xc538'),
                    engine.unknown_callee('unwind opcode decoder entry 0xc94c'),
                    lookup.unknown_callee('lookup transitive callees not composed here')],
                exceptional=dict(direct_first_raise_from_high=direct_raise.current-window.high,
                    helper_first_raise_from_high=helper_raise.current-window.high,
                    transitive_depth_bound=None,cleanup_qualified=False))
    return result


def inspect(data,exercise_mutations=False):
    previous = locking.inspect(data)
    rows,_ = diagnostic.status.sdk.pe.linked(data)
    bodies = {n:diagnostic.extract(rows,rva,size,True) for n,(rva,size,_) in BODIES.items()}
    table = diagnostic.extract(rows,TABLE_RVA,len(TABLE),False)
    check_bodies(bodies)
    check_edges(bodies)
    check_table(table)
    return dict(schema=1,status='SAVED_UNWIND_ENGINE_FRAMES_NOT_UNWIND_QUALIFICATION',
        image_sha256=previous['image_sha256'],version_observed=previous['version_observed'],
        bodies={n:dict(rva=rva,bytes=size,sha256=digest) for n,(rva,size,digest) in BODIES.items()},
        table=dict(rva=TABLE_RVA,bytes=len(TABLE),sha256=hashlib.sha256(table).hexdigest()),
        direct_transfers=len(EDGES),
        mutations_rejected=mutations(bodies,table) if exercise_mutations else None,
        geometry={str(c):geometry(Window(0,65536),c) for c in diagnostic.CAPACITIES},
        loaded_module_identity_proven=False,native_enclave_run_added=False,
        whole_image_qualified=False,production_qualified=False,
        maximum_transitive_depth_qualified=False,exception_unwind_cleanup_qualified=False,
        arbitrary_metadata_bounds_qualified=False,context_destination_bounds_qualified=False,
        sdk_self_erasure_claimed=False,
        side_effects=[
            'engine updates supplied context including register bank stack pointer and instruction pointer',
            'optional output pointers can receive handler addresses and saved-register locations',
            'engine reuses adapter stack slot at adapter RSP+80',
            'nested lookup passes null history but has its own transitive callees',
            'invalid chained metadata or opcode can call recursive status raiser',
            'normal epilogue restores saved registers without erasing the save slots'],
        unresolved=[r for r in previous['unresolved'] if r['rva'] != 0xcf78] +
            [dict(rva=0xc538,reason='epilogue interpreter'),
             dict(rva=0xc94c,reason='unwind opcode decoder')],
        residuals=previous['residuals'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sdk',type=Path)
    parser.add_argument('--mutations',action='store_true')
    args = parser.parse_args()
    print(json.dumps(inspect(args.sdk.read_bytes(),args.mutations),indent=2))
