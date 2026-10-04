"""Selected dispatch helper bounds and writes; not arbitrary unwind validation."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_sdk_dispatch as dispatch
from windows_enclave_frame_geometry import Frame, Window

diagnostic = dispatch.diagnostic
require = dispatch.require
BODIES = {
    'stack_bounds': (0x16d9c,44,'17f1673070558f0128c80020dc2593bc554374dfe6080b14ff1e5042a655cb17'),
    'stack_point': (0x172fc,21,'9d76b03da7427496b484290e61dec6393970933d8e36b274803366c86690989f'),
    'copy': (0x93b8,452,'cc35daace57068b0fec72c8ef6c44a0682f6fa6ea19c1de6dd92d938bb1368b8'),
    'adapter': (0xc3f0,207,'6324a08dc257952d12358001750825387caff6f9393ff35040e3eedfba24f6eb'),
}
EDGES = (('adapter',0xc423,0x166f8),('adapter',0xc49c,0xcf78))
ANCHORS = (
    ('stack_bounds',0x16d9c,'654c8b0425300000004c8d0c24498b4008488902498b4010488901'),
    ('stack_point',0x172fc,'f6c207750d483b117208493b100f92c0c3cc32c0c3'),
    ('copy',0x93b8,'483bd1750d8b4230254f001000894130c3'),
    ('copy',0x93ca,'836130008b4230250f001000894130'),
    ('copy',0x9517,'488d82000100000f10004881c100010000ba80000000'),
    ('copy',0x9560,'0f1040700f114411f00f100c100f110c110f104410100f11441110c3'),
    ('adapter',0xc403,'41564881ec80000000'),
    ('adapter',0xc459,'488d4424604889442448'),
)
# Exact destination intervals for distinct source/destination contexts. Adjacent
# scalar stores are combined; untouched segment fields are not included.
COPY_WRITES = ((48,4),(52,4),(56,2),(66,2),(68,4),
               (144,40),(216,40),(256,160),(512,160))


def check_bodies(bodies):
    require(set(bodies) == set(BODIES),'complete dispatch helper population')
    for name,(_,size,digest) in BODIES.items():
        require(len(bodies[name]) == size and hashlib.sha256(bodies[name]).hexdigest() == digest,
                'dispatch helper body: '+name)


def check_edges(bodies):
    for name,address,target in EDGES:
        require(diagnostic.status.relative_target(BODIES[name][0],bodies[name],
            address-BODIES[name][0],0xe8) == target,'helper direct call')
    for name,address,hexcode in ANCHORS:
        code = bytes.fromhex(hexcode)
        offset = address-BODIES[name][0]
        require(bodies[name][offset:offset+len(code)] == code,'helper semantic anchor')


def mutations(bodies):
    check_bodies(bodies)
    count = 0
    for name,body in bodies.items():
        for index in range(len(body)):
            changed = bytearray(body)
            changed[index] ^= 1
            try: check_bodies(bodies | {name:bytes(changed)})
            except ValueError: count += 1
            else: raise AssertionError('accepted dispatch helper mutation')
    return count


def stack_point(low,high,address,aligned):
    """Faithful point predicate, NOT a span/progress or OS-metadata guarantee."""
    for value in (low,high,address): dispatch.context.integer(value,(1<<64)-1)
    require(type(aligned) is bool,'explicit helper alignment mode')
    return low <= address < high and (not aligned or address % 8 == 0)


def copy_writes(window,destination,same_object):
    require(type(destination) is int and type(same_object) is bool,'destination and exact same-object branch')
    fields = ((48,4),) if same_object else COPY_WRITES
    return [window.span('context copy destination',destination+offset,size) for offset,size in fields]


def geometry(window,capacity,exception_size):
    result = {}
    for path,row in dispatch.geometry(window,capacity,exception_size).items():
        fixed = window.high+row['frames']['dispatch_fixed']
        work = window.high+row['frames']['dispatch_dynamic']
        adapter = Frame.enter(window,work,136)
        flags = Frame.enter(window,adapter.current,40)
        engine = Frame.enter(window,adapter.current,168)
        spans = [window.span('stack-bounds leaf return',fixed-8,8),
            window.span('OS-derived low and high outputs',fixed+152,16),
            window.span('stack-point leaf return',work-8,8),
            window.span('context-copy leaf return',work-8,8),
            adapter.slot('adapter four home saves',8,32,'entry'),
            adapter.slot('adapter R14 push',-8,8,'entry'),
            adapter.slot('adapter outgoing arguments',32,48),
            adapter.slot('adapter working flag',80,4),
            adapter.slot('adapter bound/output descriptor',96,24),
            flags.slot('flags RBX push',-8,8,'entry'),
            engine.slot('engine flag aliases adapter flag',256,4)]
        result[path] = dict(illustrative_exception_size=exception_size,
            frames={n:f.current-window.high for n,f in
                    (('adapter',adapter),('flags',flags),('engine',engine))},
            spans=spans,copy_destination_writes=copy_writes(window,work+112,False),
            same_object_writes=copy_writes(window,work+112,True),
            os_stack_bounds_equal_clearing_window_proven=False,
            arbitrary_source_or_overlap_validated=False,forward_progress_proven=False,
            actual_runtime_allocation_observed=False,cleanup_qualified=False)
    return result


def inspect(data,exercise_mutations=False):
    previous = dispatch.inspect(data)
    rows,_ = diagnostic.status.sdk.pe.linked(data)
    bodies = {n:diagnostic.extract(rows,r,s,True) for n,(r,s,_) in BODIES.items()}
    check_bodies(bodies)
    check_edges(bodies)
    return dict(schema=1,status='SAVED_DISPATCH_HELPERS_POINT_AND_SELECTED_WRITE_REVIEW',
        image_sha256=previous['image_sha256'],version_observed=previous['version_observed'],
        bodies={n:dict(rva=r,bytes=s,sha256=h) for n,(r,s,h) in BODIES.items()},
        direct_transfers=len(EDGES),instruction_anchors=len(ANCHORS),
        body_byte_mutations_rejected=mutations(bodies) if exercise_mutations else None,
        geometry={str(c):geometry(Window(0,65536),c,1279) for c in diagnostic.CAPACITIES},
        loaded_module_identity_proven=False,native_enclave_run_added=False,
        whole_image_qualified=False,production_qualified=False,
        arbitrary_context_bounds_qualified=False,exception_unwind_cleanup_qualified=False,
        maximum_transitive_depth_qualified=False,sdk_self_erasure_claimed=False,
        side_effects=[
            'initial stack bounds are read through GS:0x30 and written to caller locals',
            'stack-point helper validates alignment and a point only, not access width or progress',
            'context copy masks flags differently for exact self-copy and distinct pointers',
            'distinct copy writes selected scalar and floating/vector fields, not a whole context',
            'copy leaves intermediate register contents and destination data; it is not erasure',
            'alternate adapter calls previously inspected flags and unwind engine with caller outputs'],
        unresolved=[r for r in previous['unresolved'] if r['rva'] not in
                    (0x16d9c,0x172fc,0x93b8,0xc3f0)],residuals=previous['residuals'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sdk',type=Path)
    parser.add_argument('--mutations',action='store_true')
    args = parser.parse_args()
    print(json.dumps(inspect(args.sdk.read_bytes(),args.mutations),indent=2))
