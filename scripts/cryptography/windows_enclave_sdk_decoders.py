"""Saved unwind-decoder frames and selected known-context write envelopes."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_sdk_unwind as unwind
from windows_enclave_frame_geometry import Frame, Window

diagnostic = unwind.diagnostic
require = unwind.require
BODIES = {
    'epilogue': (0xc538,962,'859b02d991aeb882f2200f247a8cccb339672acc83dd1bb4b504d7a00d32e833'),
    'opcodes': (0xc94c,1572,'f4c3633e5faf35c7c4b06f8a4e3fae0236b267eead2dcb0b24dbe4fa217f5f58'),
}
EDGES = (('epilogue',0xc5ca,0xc904),('opcodes',0xce97,0xc904),('opcodes',0xced9,0xbeb0))
ANCHORS = (
    ('epilogue',0xc547,bytes.fromhex('53565741544155415641574883ec50')),
    ('opcodes',0xc95f,bytes.fromhex('53565741564883ec78')),
    ('opcodes',0xce59,bytes.fromhex('4d8b4108498bd24803d2488b4c2460498b01488904d14c8944d108')),
)


def check_bodies(bodies):
    require(set(bodies) == set(BODIES),'complete decoder body population')
    for name,(_,size,digest) in BODIES.items():
        require(len(bodies[name]) == size and hashlib.sha256(bodies[name]).hexdigest() == digest,
                'decoder body: '+name)


def check_edges(bodies):
    for name,instruction,target in EDGES:
        require(diagnostic.status.relative_target(BODIES[name][0],bodies[name],
            instruction-BODIES[name][0],0xe8) == target,'decoder call: '+name)
    for name,address,code in ANCHORS:
        offset = address-BODIES[name][0]
        require(bodies[name][offset:offset+len(code)] == code,'decoder frame/vector anchor: '+name)


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
                raise AssertionError('accepted decoder body mutation')
    return count


def context_write(window,context,bank,index):
    """Model only the inspected four-bit register selector, not arbitrary inputs."""
    require(bank in ('gpr','vector') and type(index) is int and 0 <= index < 16,
            'reviewed register bank and four-bit selector')
    require(type(context) is int,'known context base')
    base,width = (0x78,8) if bank == 'gpr' else (0x1a0,16)
    return window.span(bank+' register '+str(index),context+base+index*width,width)


def geometry(window,capacity):
    result = {}
    for path,origins in unwind.geometry(window,capacity).items():
        result[path] = {}
        for origin,row in origins.items():
            caller = window.high+row['frames']['engine']
            epilogue = Frame.enter(window,caller,136)
            opcodes = Frame.enter(window,caller,152)
            epilogue_slots = Frame.enter(window,epilogue.current,40)
            opcode_slots = Frame.enter(window,opcodes.current,40)
            first_raise = Frame.enter(window,opcodes.current,1432)
            helper_raise = Frame.enter(window,opcode_slots.current,1432)
            spans = [
                epilogue.slot('epilogue reused argument home slots',8,24,'entry'),
                epilogue.slot('epilogue fourth home slot counter',32,4,'entry'),
                epilogue.slot('epilogue seven pushes',-56,56,'entry'),
                epilogue.slot('epilogue locals and staged pointers',32,40),
                opcodes.slot('opcode four argument home saves',8,32,'entry'),
                opcodes.slot('opcode four pushes',-32,32,'entry'),
                opcodes.slot('opcode locals and staged pointers',32,72),
                epilogue_slots.slot('epilogue slot-helper opcode home',8,2,'entry'),
                opcode_slots.slot('opcode slot-helper opcode home',8,2,'entry'),
            ]
            # For these two known invalid-argument origins only: engine is
            # invalid.current-320, context is invalid.current+256.
            context = caller+576
            for bank in ('gpr','vector'):
                for index in range(16): context_write(window,context,bank,index)
            envelopes = [window.span('known context GPR bank',context+0x78,128),
                window.span('known context instruction pointer',context+0xf8,8),
                window.span('known context vector bank',context+0x1a0,256)]
            result[path][origin] = dict(frames={n:f.current-window.high for n,f in
                (('epilogue',epilogue),('opcodes',opcodes),('epilogue_slots',epilogue_slots),
                 ('opcode_slots',opcode_slots))},spans=spans,
                known_context_base_from_high=context-window.high,context_write_envelopes=envelopes,
                exceptional=dict(direct_first_raise_from_high=first_raise.current-window.high,
                    helper_first_raise_from_high=helper_raise.current-window.high,
                    transitive_depth_bound=None,cleanup_qualified=False))
    return result


def inspect(data,exercise_mutations=False):
    previous = unwind.inspect(data)
    rows,_ = diagnostic.status.sdk.pe.linked(data)
    bodies = {n:diagnostic.extract(rows,rva,size,True) for n,(rva,size,_) in BODIES.items()}
    check_bodies(bodies)
    check_edges(bodies)
    return dict(schema=1,status='SAVED_DECODER_FRAMES_NOT_EXCEPTION_QUALIFICATION',
        image_sha256=previous['image_sha256'],version_observed=previous['version_observed'],
        bodies={n:dict(rva=rva,bytes=size,sha256=digest) for n,(rva,size,digest) in BODIES.items()},
        direct_transfers=len(EDGES),instruction_anchors=len(ANCHORS),
        body_byte_mutations_rejected=mutations(bodies) if exercise_mutations else None,
        geometry={str(c):geometry(Window(0,65536),c) for c in diagnostic.CAPACITIES},
        loaded_module_identity_proven=False,native_enclave_run_added=False,
        whole_image_qualified=False,production_qualified=False,
        maximum_transitive_depth_qualified=False,exception_unwind_cleanup_qualified=False,
        arbitrary_metadata_bounds_qualified=False,arbitrary_context_bounds_qualified=False,
        optional_saved_location_storage_qualified=False,sdk_self_erasure_claimed=False,
        side_effects=[
            'decoder context writes restore scalar registers stack pointer instruction pointer and vector pairs',
            'known context write envelopes are limited to the two modeled invalid-argument origins',
            'optional saved-location arrays can receive source addresses through caller pointers',
            'epilogue chain overflow returns status while opcode chain overflow can raise recursively',
            'normal epilogues restore registers without erasing stack saves'],
        unresolved=[r for r in previous['unresolved'] if r['rva'] not in (0xc538,0xc94c)],
        residuals=previous['residuals'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sdk',type=Path)
    parser.add_argument('--mutations',action='store_true')
    args = parser.parse_args()
    print(json.dumps(inspect(args.sdk.read_bytes(),args.mutations),indent=2))
