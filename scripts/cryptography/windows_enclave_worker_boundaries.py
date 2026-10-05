"""Bind all saved sequential worker entry/transport boundaries, not their callees."""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_archive as archive
import windows_enclave_caller_object as obj
import windows_enclave_route_transport as transport

shared = transport.shared
require, digest = shared.require, shared.digest
SPEC = shared.CATALOG.with_name('worker-boundaries-20261005.json')
SPEC_HASH = '9ad55f2123bf44402901bf61b95f645935d869aeff004d2a83a8be303910f352'


def specification(raw):
    require(digest(raw) == SPEC_HASH, 'saved worker boundary review identity')
    result = json.loads(raw)
    require(result['schema'] == 1 and len(result['profiles']) == 17, 'worker population')
    return result


def call_population(data):
    rows, symbols = obj.tables(data); result = []
    for index, section in enumerate(rows, 1):
        if not section['flags'] & 0x20000000: continue
        for at, ref in obj.relocations(data, section, symbols).items():
            name = symbols[ref['symbol']]['name']
            if not name.startswith('Public') or name == 'PublicProbeAbort': continue
            owners = [s for s in symbols.values() if s['section'] == index and s['kind'] == 0x20]
            require(len(owners) == 1 and owners[0]['value'] == 0, 'one complete transport caller')
            require(ref['kind'] == 4 and 0 < at <= len(section['code'])-4 and
                    section['code'][at-1] == 0xe8 and section['code'][at:at+4] == bytes(4),
                    'direct zero-addend transport call')
            result.append([owners[0]['name'], at, name])
    return sorted(result)


def body_check(code, refs, pin):
    require(len(code) == pin['bytes'] and digest(code) == pin['code_sha256'], 'complete worker/caller body')
    require(digest(shared.encoded(refs)) == pin['refs_sha256'], 'complete worker/caller relocations')


def reconcile(profile, records, parent, callbacks):
    require(set(records) == set(profile['functions']), 'complete boundary caller set')
    require(records['RetainedWork']['rva'] == parent['retained_worker_rva'], 'C entry calls this worker')
    for name, record in records.items():
        require(record['image_sha256'] == parent['image_sha256'], 'same worker image')
        frames = record['unwind']
        require([f['stack_bytes'] for f in frames] == profile['functions'][name]['stack_bytes'] and
                len(frames) == 1 and frames[0]['chain'] is None and not frames[0]['saved_registers'],
                'complete fixed boundary frame, no chain or saved vector slots')
        # Bind every direct edge between the selected callers as well as C entry.
        for callee, address in record['reference_targets'].items():
            if callee in records:
                require(records[callee]['rva'] == address, 'same direct Rust boundary callee')
    for name, offset, callee in profile['calls']:
        refs = [r for r in records[name]['references'] if r['offset'] == offset]
        require(len(refs) == 1 and refs[0]['symbol'] == callee and
                refs[0]['addend'] == refs[0]['trailing'] == 0, 'same callback operand')
        require(callee in callbacks and records[name]['reference_targets'][callee] == callbacks[callee],
                'actual Rust-to-reviewed-C transport target')


def inspect(data, native, image, wrapper, profile, transport_record, prefix, mutate=False):
    require(digest(data) == profile['object_sha256'], 'saved worker member identity')
    require(call_population(data) == profile['calls'], 'all executable direct transport references')
    parent = shared.inspect(native, image, wrapper); records = {}; mutations = 0
    for name, pin in profile['functions'].items():
        code, refs = shared.caller.function(data, name); body_check(code, refs, pin)
        records[name] = shared.caller.bind(data, image, name)
        if mutate:
            for index in range(len(code)):
                bad = bytearray(code); bad[index] ^= 1
                try: body_check(bad, refs, pin)
                except ValueError: mutations += 1
                else: raise AssertionError('accepted actual worker boundary byte mutation')
    require(transport_record['image_sha256'] == digest(image) and
            transport_record['route'] == profile['route'], 'same reviewed transport record')
    targets = {prefix+role:record['rva'] for role,record in transport_record['records'].items()}
    reconcile(profile, records, parent, targets)
    compact = {name:dict(rva=r['rva'], bytes=r['size'], stack_bytes=r['unwind'][0]['stack_bytes'],
                        reference_targets=r['reference_targets']) for name,r in records.items()}
    return dict(route=profile['route'], image_sha256=digest(image), object_sha256=digest(data),
                boundaries=compact, transport_calls=profile['calls'], actual_body_byte_mutations_rejected=mutations,
                entry_steady_rsp_from_window_high=-104-records['RetainedWork']['unwind'][0]['stack_bytes'],
                worker_entry_and_transport_edges_bound=True, transitive_callee_semantics_qualified=False,
                indirect_dispatch_qualified=False, maximum_whole_image_depth_qualified=False,
                loaded_application_iat_proven=False, whole_image_qualified=False)


def collect(base, raw, spec_raw, templates_raw, mutate=False):
    rows = shared.catalog(raw)[1:]; spec = specification(spec_raw)
    templates = transport.specification(templates_raw)
    require([r['route'] for r in rows] == [p['route'] for p in spec['profiles']] ==
            [p['route'] for p in templates['profiles']], 'identical complete route populations')
    wrapper = (base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes()
    sdk = (base/'sdk-system32-review/vertdll.dll').read_bytes(); shared.sdk.sdk_review.inspect(sdk)
    results = []
    for row, profile, tp in zip(rows, spec['profiles'], templates['profiles']):
        directory = (base/row['object']).parent; lib = (directory/'normal_rust.lib').read_bytes()
        require(digest(lib) == profile['archive_sha256'], 'saved archive identity')
        all_members = archive.members(lib)
        require(profile['member'] in all_members, 'selected named archive member')
        for name, expected in profile['source_sha256'].items():
            require(digest((directory/name).read_bytes()) == expected, 'saved reviewed worker/resident source')
        native, image = (base/row['object']).read_bytes(), (base/row['image']).read_bytes()
        require(digest(native) == row['object_sha256'] and digest(image) == row['sha256'], 'saved input identity')
        tr = transport.inspect(native, image, wrapper, sdk, tp, templates['templates'])
        result = inspect(all_members[profile['member']], native, image, wrapper, profile, tr, tp['prefix'], mutate)
        result.update(archive_sha256=profile['archive_sha256'], source_sha256=profile['source_sha256'])
        results.append(result)
    return dict(schema=1, date='2026-10-05', status='SAVED_SEQUENTIAL_WORKER_BOUNDARIES', records=results,
                boundary_spec_sha256=SPEC_HASH, transport_spec_sha256=transport.SPEC_HASH,
                body_bindings=sum(len(r['boundaries']) for r in results),
                direct_transport_calls=sum(len(r['transport_calls']) for r in results),
                independently_verified=False, native_run_added=False, release_gate_changed=False,
                source_review_implies_transitive_machine_cleanup=False, whole_image_qualified=False)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('saved_directory', type=Path)
    p.add_argument('--catalog', type=Path, default=shared.CATALOG); p.add_argument('--spec', type=Path, default=SPEC)
    p.add_argument('--templates', type=Path, default=transport.SPEC); p.add_argument('--mutate', action='store_true')
    p.add_argument('--output', type=Path); a = p.parse_args()
    result = collect(a.saved_directory, a.catalog.read_bytes(), a.spec.read_bytes(), a.templates.read_bytes(), a.mutate)
    paths = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    paths.update((Path(__file__), Path(__file__).with_name('test-windows-enclave-worker-boundaries.py')))
    result['source_sha256'] = {p.name:digest(p.read_bytes()) for p in sorted(paths)}
    text = json.dumps(result, indent=2)+'\n'
    if a.output: a.output.write_text(text, encoding='utf-8')
    else: print(text, end='')
