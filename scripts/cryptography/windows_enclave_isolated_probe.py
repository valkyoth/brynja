"""Bounded native PUBLIC-vector canary; no whole-image or production claim."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from windows_enclave_lifecycle import Native
from windows_enclave_window_lock import Handshake
from windows_protection_api import Windows
from windows_protection_probe import require
from windows_enclave_sha256_build import vectors


class Request(c.Structure):
    _fields_ = [(name, c.c_size_t) for name in ('input', 'length', 'output', 'control')]


def cases():
    return [('vector-'+str(i), data, 1, 1) for i, data in enumerate(vectors())] + [
        (name, b'abc', status, body) for name, status, body in
        [('bad-descriptor', 11, 0), ('oversize', 12, 0), ('unknown-control', 12, 0),
         ('identity-drift', 13, 0), ('bad-input', 14, 0), ('bad-output', 16, 1),
         ('deny', 15, 0), ('reentry', 1, 1), ('reuse', 1, 1)]]


def validate(rows):
    require(type(rows) is list and len(rows) == len(cases()), 'complete canary campaign')
    normal = ['admit', 'lock', 'all-pages-locked', 'admit-ack', 'clear-confirmed',
              'still-locked', 'unlock', 'finish-ack']
    for row, (name, _, status, body) in zip(rows, cases(), strict=True):
        require(type(row) is dict and set(row) == {'case', 'status', 'observations',
                'callback_trace', 'reentry'}, 'exact case fields')
        require(type(row['status']) is int and row['status'] == status and row['case'] == name,
                'ordered case/status')
        obs = row['observations']
        require(type(obs) is list and all(type(v) is int for v in obs) and
                obs == [body, int(status == 1), status, 1], 'exact retirement observations')
        trace = normal if body else ['admit', 'deny', 'clear-confirmed', 'finish-ack'] if name == 'deny' else []
        require(row['callback_trace'] == trace, 'exact cleanup callback order')
        require(row['reentry'] == ([0] if name == 'reentry' else []), 'reentry rejection')


def validate_dirty(result):
    require(result.returncode == 0xc0000409 and result.stdout == result.stderr == '',
            'cleanup omission must fast-fail the child, not return or report success')


def exercise(image):
    api, host = Native(), Windows()
    base = api.create()
    initialized = False
    rows = []
    try:
        loaded, error = api.load(base, image)
        require(loaded, 'canary load: '+str(error))
        api.initialize(base)
        initialized = True
        def export(name):
            return api.check(api.GetProcAddress(base, name.encode()), name)
        work, observe, register = map(export, ('PublicIsolatedSha256', 'PublicIsolatedObserve', 'PublicLockedHost'))
        callback_type = c.WINFUNCTYPE(c.c_void_p, c.c_void_p)
        for name, data, expected, body in cases():
            source = c.create_string_buffer(data)
            output = (c.c_ubyte * 32)(*[0xa5]*32)
            request = Request(c.addressof(source), len(data), c.addressof(output), 0)
            if name == 'oversize': request.length = 1025
            if name == 'unknown-control': request.control = 2
            if name == 'identity-drift': request.control = 1
            if name == 'bad-input': request.input = 1
            if name == 'bad-output': request.output = 1
            handshake = Handshake(host, base, deny=name == 'deny')
            nested, callback_errors = [], []
            def callback(argument):
                try:
                    if name == 'reentry' and argument is not None and argument & 15 == 0:
                        nested.append(api.call(work, c.addressof(request)))
                    return handshake(argument)
                except BaseException as error:
                    callback_errors.append(str(error))
                    return 0
            bound = callback_type(callback)
            require(api.call(register, c.cast(bound, c.c_void_p).value) == 1, 'register callback')
            value = api.call(work, 1 if name == 'bad-descriptor' else c.addressof(request))
            require(not callback_errors and handshake.error is None, 'callback failed: '+repr(callback_errors))
            require(not handshake.locked, 'normal path leaked host lock')
            observations = [api.call(observe, i) for i in range(4)]
            require(value == expected and observations == [body, int(expected == 1), expected, 1],
                    'exact status/body/publish/staging retirement: '+name+' '+repr((value, observations)))
            digest = bytes(output)
            require(digest == (hashlib.sha256(data).digest() if expected == 1 else bytes([0xa5]*32)),
                    'independent digest or transactional output: '+name)
            require(nested == ([0] if name == 'reentry' else []), 'reentry must reject')
            if body:
                require(handshake.phase == 'finished' and 'clear-confirmed' in handshake.trace,
                        'compute must retire before return')
            rows.append(dict(case=name, status=value, observations=observations,
                             callback_trace=handshake.trace, reentry=nested))
    finally:
        try:
            if initialized: api.terminate(base)
        finally:
            api.delete(base)
    validate(rows)
    return dict(schema=1, status='PUBLIC_CANARY_NATIVE_FUNCTIONAL_ONLY', cases=rows,
                native_machine=api.machine,
                production_qualified=False, whole_image_qualified=False,
                emitted_compute_graph_qualified=False, staging_residency_qualified=False,
                terminated=True, deleted=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--child', action='store_true')
    parser.add_argument('--expect-dirty', action='store_true')
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    if args.child:
        require(not args.expect_dirty, 'dirty expectation belongs to parent')
        print(json.dumps(exercise(image)))
    else:
        before = hashlib.sha256(image.read_bytes()).hexdigest()
        result = subprocess.run([sys.executable, __file__, str(image), '--child'],
                                capture_output=True, text=True, timeout=90)
        if args.expect_dirty:
            validate_dirty(result)
            record = dict(status='PUBLIC_CANARY_DIRTY_FASTFAIL_CONTROL',
                          returncode=result.returncode, cleanup_success_claimed=False,
                          production_qualified=False)
        else:
            require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) < 65536,
                    'bounded clean canary child: '+result.stderr[-4000:])
            record = json.loads(result.stdout)
            validate(record['cases'])
        require(before == hashlib.sha256(image.read_bytes()).hexdigest(), 'image changed')
        record['image_sha256'] = before
        record['windows_build'] = sys.getwindowsversion().build
        record['python'] = sys.version
        record['source_sha256'] = {p.name:hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted({Path(m.__file__) for n,m in sys.modules.items()
                            if n.startswith(('windows_enclave_', 'windows_protection_'))}
                            | {Path(__file__)})}
        print(json.dumps(record, indent=2))
