"""Saved-SDK lock frames; not lock correctness or exceptional-depth proof."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_sdk_directory as directory
from windows_enclave_frame_geometry import Frame, Window

diagnostic = directory.diagnostic
require = directory.require
BODIES = {
    'lock': (0x9650,31,'f4ac1d555a85abe97a89c9fd5d316cb08b9950ec1c0d2a91e7139ee31faa8ddf'),
    'unlock': (0x96e0,183,'f91912ff24a276c6ca047f069d09c91ddc614d31b933baba93d6fdd9f4f7a149'),
    'acquire_slow': (0x9a18,479,'001e14901046cbaa5720f7301c20085e1b4b26df551fa757e35b0449f6329125'),
    'queue_link': (0x9c00,79,'ae8dc3748de847944c8dc01f5f084ce33e5df41327093cc0d455066215fb0440'),
    'wake': (0x9d3c,182,'72d36ed4995a7367ccb7035214ccfff0a791c7acd2b73a332e10acfedfde04c5'),
    'backoff': (0x17578,133,'8ecc1b16b5435a77885623874f93d304ed5a96b4fe1ef7b3bf37790f40167d44'),
    'wait_stub': (0x1ce00,11,'6b8fb6afe43835d4ca5f7413270bf612173878b83b1df8131b0b1a699808a02a'),
    'signal_stub': (0x1cd60,11,'69f61928d3c7e7baa1ebffdd6431f0460947a29cae02831ddd5faacd125bfd68'),
    'raise_status': (0xbeb0,107,'88b0ea51f2e4750f18499e34df74eff52478502d194ed40a69ae8594e353aa1f'),
}
EDGES = (
    ('lock',0x9665,0xe8,0x9a18), ('unlock',0x9702,0xe8,0xbeb0),
    ('unlock',0x978d,0xe8,0x9d3c), ('acquire_slow',0x9aee,0xe8,0x17578),
    ('acquire_slow',0x9b29,0xe8,0x9c00), ('acquire_slow',0x9bd1,0xe8,0x1ce00),
    ('queue_link',0x9c4a,0xe9,0x9d3c), ('wake',0x9dda,0xe8,0x1cd60),
    ('raise_status',0xbec6,0xe8,0x1f030), ('raise_status',0xbefa,0xe8,0x1b50),
    ('raise_status',0xbf15,0xe8,0xbeb0),
)


def check_bodies(bodies):
    require(set(bodies) == set(BODIES),'complete locking body population')
    for name,(_,size,digest) in BODIES.items():
        require(len(bodies[name]) == size and hashlib.sha256(bodies[name]).hexdigest() == digest,
                'locking body: '+name)


def check_edges(bodies):
    for name,instruction,opcode,target in EDGES:
        require(diagnostic.status.relative_target(BODIES[name][0],bodies[name],
            instruction-BODIES[name][0],opcode) == target,'locking transfer: '+name)


def mutations(bodies):
    check_bodies(bodies)
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
                raise AssertionError('accepted locking body mutation')
    return count


def geometry(window,capacity):
    result = {}
    for path,origins in directory.runtime.geometry(window,capacity).items():
        result[path] = {}
        for origin,row in origins.items():
            module = window.high+row['frames']['module']
            lock = Frame.enter(window,module,40)
            slow = Frame.enter(window,lock.current,104)
            # The queue leaf tail-jumps to wake, reusing its return address.
            tail_wake = Frame.enter(window,slow.current,40)
            unlock = Frame.enter(window,module,40)
            direct_wake = Frame.enter(window,unlock.current,40)
            first_raise = Frame.enter(window,unlock.current,1432)
            spans = [
                slow.slot('slow argument and RBX RSI home saves',16,24,'entry'),
                slow.slot('slow RBP RDI R12 pushes',-24,24,'entry'),
                slow.slot('slow 48-byte wait node',32,48),
                # backoff's input is low four bytes of the saved RDX home slot.
                slow.slot('backoff input counter',16,4,'entry'),
                window.span('backoff leaf return/home',slow.current-8,40),
                window.span('queue leaf return/home',slow.current-8,40),
                window.span('wait syscall return',slow.current-8,8),
                tail_wake.slot('tail wake RBX home',8,8,'entry'),
                tail_wake.slot('tail wake RDI push',-8,8,'entry'),
                window.span('tail wake signal return',tail_wake.current-8,8),
                direct_wake.slot('direct wake RBX home',8,8,'entry'),
                direct_wake.slot('direct wake RDI push',-8,8,'entry'),
                window.span('direct wake signal return',direct_wake.current-8,8),
            ]
            result[path][origin] = dict(frames={n:f.current-window.high for n,f in
                (('lock',lock),('slow',slow),('tail_wake',tail_wake),
                 ('unlock',unlock),('direct_wake',direct_wake))},spans=spans,
                selected_ordinary_low_from_high=tail_wake.current-8-window.high,
                exceptional=dict(first_raise_frame_from_high=first_raise.current-window.high,
                    recursive_frame_step_bytes=1440,transitive_depth_bound=None,
                    cleanup_qualified=False,
                    unknown_callee=first_raise.unknown_callee('context/raise helper entry')))
    return result


def inspect(data,exercise_mutations=False):
    previous = directory.inspect(data)
    rows,_ = diagnostic.status.sdk.pe.linked(data)
    bodies = {n:diagnostic.extract(rows,rva,size,True) for n,(rva,size,_) in BODIES.items()}
    check_bodies(bodies)
    check_edges(bodies)
    return dict(schema=1,status='SAVED_SDK_LOCK_FRAMES_NOT_CONCURRENCY_QUALIFICATION',
        image_sha256=previous['image_sha256'],version_observed=previous['version_observed'],
        bodies={n:dict(rva=rva,bytes=size,sha256=digest) for n,(rva,size,digest) in BODIES.items()},
        direct_transfers=len(EDGES),
        body_byte_mutations_rejected=mutations(bodies) if exercise_mutations else None,
        geometry={str(c):geometry(Window(0,65536),c) for c in diagnostic.CAPACITIES},
        loaded_module_identity_proven=False,native_enclave_run_added=False,
        whole_image_qualified=False,production_qualified=False,
        maximum_transitive_depth_qualified=False,exception_unwind_cleanup_qualified=False,
        lock_concurrency_qualified=False,wait_node_reclamation_proven=False,
        external_storage_erasure_proven=False,kernel_storage_qualified=False,
        sdk_self_erasure_claimed=False,
        side_effects=[
            'module caller uses shared lock at saved-image RVA 0x28d68',
            'slow acquire publishes a tagged pointer to its stack wait node',
            'queue and wake modify linked wait nodes potentially owned by other threads',
            'wait node initialization is not an exit wipe',
            'backoff uses thread/system data and modifies the supplied counter',
            'wait and signal syscalls have no software stack adjustment in these stubs',
            'invalid unlock can enter a recursive status-raising path'],
        unresolved=[r for r in previous['unresolved'] if r['rva'] not in (0x9650,0x96e0)] +
            [dict(rva=0x1b50,reason='context/raise helper and recursive exceptional path')],
        residuals=previous['residuals'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sdk',type=Path)
    parser.add_argument('--mutations',action='store_true')
    args = parser.parse_args()
    print(json.dumps(inspect(args.sdk.read_bytes(),args.mutations),indent=2))
