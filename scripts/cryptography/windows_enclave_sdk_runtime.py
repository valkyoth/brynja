"""Selected saved-SDK lookup/unwind adapters, not an OS unwinder proof."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_sdk_conversion as conversion
from windows_enclave_frame_geometry import Frame, Window

BODIES = {
    'lookup': (0x8b60, 679, '3ac1ecb56ca3376765deb892ac6c85ef27082a0e7bf96430006d451f9fcf82d6'),
    'module_lookup': (0x15ce8, 351, '81c18041e2a82be1b3b57b8e302a9fc40ccf23bc3b81849fa721f40cac018ef6'),
    'normalize_entry': (0xc4c8, 23, 'b25322a66e233567793bf4aa71abcac1465d9964db6c1d5effd9ba513a6d8873'),
    'unwind_adapter': (0xc320, 198, '2337c861aeaae91384c048201bcd48ea02207671d3777efb4821cf1b34d68e54'),
    'context_flags': (0x166f8, 192, '8e7d5a011323c8e0b9f2d1d5e3001a9cc87ad058eb593b1df9fbbf676d564637'),
    'flags_adapter': (0x167c0, 19, 'ac13382edfad44a4a696c3a0159d0c85b8a8412f27fdb7e8d7e555a87b12443f'),
    'flags_check': (0x167dc, 192, 'dae4b78724a09fe3e60ba85f8fb8443918bf2a86edb48034be39c23a49ec8433'),
    'module_query': (0x1cce0, 11, 'd9bc08a78b194736485339427e2ade4e81302903fa39b595f82e0dceca889790'),
    'directory_adapter': (0x159f8, 53, '99b45420d0cd2d2e92437b93133317e6d90a4d2ad40071d040b4de5784967cbd'),
}
EDGES = (
    ('lookup',0x8cef,0xe8,0x15ce8), ('lookup',0x8ded,0xe8,0xc4c8),
    ('module_lookup',0x15d1f,0xe8,0x9650), ('module_lookup',0x15d99,0xe8,0x96e0),
    ('module_lookup',0x15de1,0xe8,0x1cce0), ('module_lookup',0x15e20,0xe8,0x159f8),
    ('unwind_adapter',0xc362,0xe8,0x166f8), ('unwind_adapter',0xc3be,0xe8,0xcf78),
    ('context_flags',0x16706,0xe8,0x167c0), ('flags_adapter',0x167ce,0xe9,0x167dc),
    ('directory_adapter',0x15a11,0xe8,0xdf94),
)


def check_bodies(bodies):
    conversion.require(set(bodies) == set(BODIES), 'complete runtime-adapter population')
    for name,(_,size,digest) in BODIES.items():
        conversion.require(len(bodies[name]) == size and
            hashlib.sha256(bodies[name]).hexdigest() == digest, 'runtime body: '+name)


def check_edges(bodies):
    for name,instruction,opcode,target in EDGES:
        conversion.require(conversion.formatter.diagnostic.status.relative_target(
            BODIES[name][0],bodies[name],instruction-BODIES[name][0],opcode) == target,
            'runtime transfer: '+name)


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
                raise AssertionError('accepted runtime-adapter body mutation')
    return count


def geometry(window, capacity):
    result = {}
    previous = conversion.geometry(window,capacity)
    for path,row in previous.items():
        result[path] = {}
        for origin,invalid in row['invalid_paths'].items():
            caller = window.high+invalid['frame_from_high']
            lookup = Frame.enter(window,caller,72)
            module = Frame.enter(window,lookup.current,88)
            directory = Frame.enter(window,module.current,40)
            unwind = Frame.enter(window,caller,136)
            flags = Frame.enter(window,unwind.current,40)
            spans = [
                lookup.slot('lookup three home saves',8,24,'entry'),
                lookup.slot('lookup RDI push',-8,8,'entry'),
                lookup.slot('lookup module descriptor',32,24),
                module.slot('module RBX home save',8,8,'entry'),
                module.slot('module RSI home save',24,8,'entry'),
                module.slot('module RDI push',-8,8,'entry'),
                module.slot('module call args and query descriptor',32,40),
                module.slot('module result home slot',16,8,'entry'),
                directory.slot('directory RBX home save',8,8,'entry'),
                directory.slot('directory RDI push',-8,8,'entry'),
                unwind.slot('unwind four home saves',8,32,'entry'),
                unwind.slot('unwind R14 push',-8,8,'entry'),
                unwind.slot('unwind staged args and results',32,96),
                flags.slot('context validator RBX push',-8,8,'entry'),
                # flags_adapter tail-jumps: same return address and home area.
                window.span('flags leaf return and RBX home save',flags.current-8,16),
                window.span('query syscall return/home',module.current-8,40),
                window.span('normalize leaf return/home',lookup.current-8,40),
                window.span('known invalid-context flags destination',caller+256+48,4)]
            result[path][origin] = dict(frames={n:f.current-window.high for n,f in
                (('lookup',lookup),('module',module),('directory',directory),
                 ('unwind',unwind),('flags',flags))},spans=spans,
                unknown_callees=[module.unknown_callee('module locking helper entry'),
                    directory.unknown_callee('directory parser entry'),
                    unwind.unknown_callee('unwind engine entry')])
    return result


def inspect(data, exercise_mutations=False):
    previous = conversion.inspect(data)
    sections,_ = conversion.formatter.diagnostic.status.sdk.pe.linked(data)
    bodies = {n:conversion.formatter.diagnostic.extract(sections,rva,size,True)
              for n,(rva,size,_) in BODIES.items()}
    check_bodies(bodies)
    check_edges(bodies)
    return dict(schema=1,status='SAVED_SDK_RUNTIME_ADAPTERS_NOT_UNWIND_QUALIFICATION',
        image_sha256=previous['image_sha256'],version_observed=previous['version_observed'],
        bodies={n:dict(rva=rva,bytes=size,sha256=digest) for n,(rva,size,digest) in BODIES.items()},
        direct_transfers=len(EDGES),
        body_byte_mutations_rejected=mutations(bodies) if exercise_mutations else None,
        geometry={str(c):geometry(Window(0,65536),c)
                  for c in conversion.formatter.diagnostic.CAPACITIES},
        loaded_module_identity_proven=False,native_enclave_run_added=False,
        whole_image_qualified=False,production_qualified=False,
        maximum_transitive_depth_qualified=False,exception_unwind_cleanup_qualified=False,
        generic_context_bounds_qualified=False,kernel_query_storage_qualified=False,
        history_storage_cleared_by_window_proven=False,
        side_effects=[
            'lookup writes output image base and can update non-null caller history',
            'reviewed invalid-argument caller passes a null history pointer',
            'module lookup reads cache globals and calls locking/query helpers',
            'context validator updates four-byte context flags at offset 0x30',
            'flags leaf may write optional result; reviewed validator passes null'],
        unresolved=[dict(rva=rva,reason=reason) for rva,reason in (
            (0x9650,'module-cache locking'),(0x96e0,'module-cache unlocking'),
            (0xdf94,'image directory parsing'),(0xcf78,'unwind engine'),
            (0xbc90,'exception dispatch'),(0x1160,'fatal cookie-failure path'))],
        residuals=previous['residuals'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sdk',type=Path)
    parser.add_argument('--mutations',action='store_true')
    args = parser.parse_args()
    print(json.dumps(inspect(args.sdk.read_bytes(),args.mutations),indent=2))
