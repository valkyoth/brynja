"""Fixed saved-SDK directory frames, not arbitrary PE or exception safety."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_sdk_runtime as runtime
from windows_enclave_frame_geometry import Frame, Window

diagnostic = runtime.conversion.formatter.diagnostic
require = runtime.conversion.require
BODIES = {
    'directory_result': (0xdf94,48,'88c2496ff67439bfeee4e93b830f5c6f76b236b11b7bc1992a98761eef8cb4a1'),
    'directory_parse': (0xe010,264,'35531ae6298ffc6fa5e0aa2ca41f29fbcdad180a23c15a492a170b441cd9cc9a'),
    'rva_translate': (0xdf64,40,'cdf2fc5d4b1b3d7c27021963bc2b84a0ac56f9e2d99710d1e62c9a5e7ecbea0a'),
    'section_find': (0xdfcc,58,'491782c04b79e1dbc2655b5861ee6b11f3531cf2a07bcdc3c3964190b86b8396'),
    'header_find': (0xba20,258,'524f705b302e91ddb57885d6241b62ba1e2e7c25ee43ecc20971342696a2835b'),
}
EDGES = (
    ('directory_result',0xdfab,0xe010), ('directory_parse',0xe065,0xba20),
    ('directory_parse',0xe0ae,0xdf64), ('rva_translate',0xdf6b,0xdfcc),
)
# These caller instructions select flag 1 and size 0 for header_find: that
# helper's optional size checks are NOT active on this reviewed call path.
HEADER_CALL = (0xe056,bytes.fromhex('4533c04c8d4c2440488bd7418d4801'))


def check_bodies(bodies):
    require(set(bodies) == set(BODIES),'complete directory body population')
    for name,(_,size,digest) in BODIES.items():
        require(len(bodies[name]) == size and hashlib.sha256(bodies[name]).hexdigest() == digest,
                'directory body: '+name)


def check_edges(bodies):
    for name,instruction,target in EDGES:
        require(diagnostic.status.relative_target(BODIES[name][0],bodies[name],
            instruction-BODIES[name][0],0xe8) == target,'directory call: '+name)
    address,code = HEADER_CALL
    offset = address-BODIES['directory_parse'][0]
    require(bodies['directory_parse'][offset:offset+len(code)] == code,
            'reviewed header flags/size/output destination')


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
                raise AssertionError('accepted directory body mutation')
    return count


def geometry(window,capacity):
    result = {}
    for path,origins in runtime.geometry(window,capacity).items():
        result[path] = {}
        for origin,row in origins.items():
            caller = window.high+row['frames']['directory']
            wrapper = Frame.enter(window,caller,72)
            parser = Frame.enter(window,wrapper.current,56)
            header = Frame.enter(window,parser.current,72)
            translate = Frame.enter(window,parser.current,40)
            spans = [
                wrapper.slot('directory result RBX push',-8,8,'entry'),
                wrapper.slot('directory result fifth argument',32,8),
                wrapper.slot('directory result pointer',48,8),
                parser.slot('parser three home saves',16,24,'entry'),
                parser.slot('parser three pushes',-24,24,'entry'),
                parser.slot('parser NT-header result home',8,8,'entry'),
                header.slot('header flags home',8,4,'entry'),
                header.slot('header output-pointer home',32,8,'entry'),
                header.slot('header RBX push',-8,8,'entry'),
                header.slot('header status offset and pointer locals',32,16),
                window.span('section leaf return/home',translate.current-8,40),
            ]
            result[path][origin] = dict(frames={n:f.current-window.high for n,f in
                (('result',wrapper),('parser',parser),('header',header),('translate',translate))},
                spans=spans,section_leaf_entry_from_high=translate.current-8-window.high,
                # Sibling calls are alternatives, not additive nesting.
                selected_low_from_high=min(header.current,translate.current-8)-window.high)
    return result


def inspect(data,exercise_mutations=False):
    previous = runtime.inspect(data)
    rows,_ = diagnostic.status.sdk.pe.linked(data)
    bodies = {n:diagnostic.extract(rows,rva,size,True) for n,(rva,size,_) in BODIES.items()}
    check_bodies(bodies)
    check_edges(bodies)
    return dict(schema=1,status='SAVED_SDK_DIRECTORY_FRAMES_NOT_PE_SAFETY_PROOF',
        image_sha256=previous['image_sha256'],version_observed=previous['version_observed'],
        bodies={n:dict(rva=rva,bytes=size,sha256=digest) for n,(rva,size,digest) in BODIES.items()},
        direct_transfers=len(EDGES),
        body_byte_mutations_rejected=mutations(bodies) if exercise_mutations else None,
        geometry={str(c):geometry(Window(0,65536),c) for c in diagnostic.CAPACITIES},
        loaded_module_identity_proven=False,native_enclave_run_added=False,
        whole_image_qualified=False,production_qualified=False,
        maximum_transitive_depth_qualified=False,exception_unwind_cleanup_qualified=False,
        arbitrary_image_bounds_qualified=False,sdk_self_erasure_claimed=False,
        header_optional_size_checks_active=False,
        side_effects=[
            'directory parser writes result pointer and size through supplied pointers',
            'header finder reads caller image and writes its supplied output pointer',
            'section finder reads section metadata without stack stores or calls',
            'normal returns restore registers but do not erase the reviewed save slots'],
        unresolved=[r for r in previous['unresolved'] if r['rva'] != 0xdf94],
        residuals=previous['residuals'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sdk',type=Path)
    parser.add_argument('--mutations',action='store_true')
    args = parser.parse_args()
    print(json.dumps(inspect(args.sdk.read_bytes(),args.mutations),indent=2))
