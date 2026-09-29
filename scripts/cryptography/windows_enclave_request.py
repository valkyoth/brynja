#!/usr/bin/env python3
"""Public snapshot/copy experiment, not a protected secret channel or release gate."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

import windows_enclave_hardened as previous
from windows_enclave_worker import WorkerNative
from windows_enclave_window_lock import Handshake, validate
from windows_protection_api import Windows
from windows_protection_probe import require

MODES = ('publish', 'mutate', 'discard', 'bad-version', 'bad-length', 'no-public',
         'bad-source', 'bad-destination', 'overflow-destination', 'hook-deny', 'overlap')
STATUS = dict(zip(MODES, (1, 1, 2, 10, 10, 10, 11, 12, 10, 13, 1)))
PUBLIC = 0x5055424c4943
SOURCES = previous.SOURCES + (
    'assurance/windows-enclave-probe/window_request.c',
    'assurance/windows-enclave-probe/window_request.rs',
    'assurance/windows-enclave-probe/window_request_tests.rs',
    'scripts/cryptography/windows_enclave_request_build.py',
    'scripts/cryptography/windows_enclave_request.py',
    'scripts/cryptography/test-windows-enclave-request.py')


class Request:
    """Public, initialized host buffers retained for the entire synchronous call."""
    def __init__(self, mode, iteration):
        require(mode in MODES and iteration in range(3), 'fixed request campaign')
        self.mode = mode
        length = (0, 56, 1024)[iteration] if mode == 'publish' else 3
        self.message = bytes((i * 17 + 3) % 256 for i in range(length))
        self.wire, self.output = (c.c_ubyte * 1072)(), (c.c_ubyte * 48)(*([0xa5] * 48))
        destination = c.addressof(self.output) + 8
        self.destination = destination
        words = [1, 1, length, destination, 32, PUBLIC]
        if mode == 'discard':
            words[1], words[3], words[4], words[5] = 2, 0, 0, 0
        elif mode == 'bad-version':
            words[0] = 2
        elif mode == 'bad-length':
            words[2] = 1025
        elif mode == 'no-public':
            words[5] = 0
        elif mode == 'bad-destination':
            words[3] = 1
        elif mode == 'overflow-destination':
            words[3] = (1 << 64) - 16
        elif mode == 'overlap':
            words[3] = c.addressof(self.wire) + 48
        self.wire[:] = struct.pack('<6Q', *words) + self.message.ljust(1024, b'\0')
        self.source = 1 if mode == 'bad-source' else c.addressof(self.wire)

    def copied(self):
        if self.mode == 'mutate':
            # Change header AND payload only after the enclave acknowledges its copy.
            self.wire[16:24] = struct.pack('<Q', 1025)
            self.wire[48:51] = b'xyz'
        return self.mode != 'hook-deny'

    def check_output(self):
        expected = hashlib.sha256(self.message).digest()
        raw = bytes(self.output)
        require(raw[:8] == raw[40:] == b'\xa5' * 8, 'host output canaries')
        if self.mode == 'overlap':
            require(bytes(self.wire[48:80]) == expected and raw == b'\xa5' * 48,
                    'explicit overlapping public output')
        elif STATUS[self.mode] == 1:
            require(raw[8:40] == expected, 'independent public SHA-256 comparison')
        else:
            require(raw == b'\xa5' * 48, 'unused host destination unchanged')
        # Only public digests, never the host address or private storage bytes.
        return expected.hex() if STATUS[self.mode] == 1 else None


class RequestHandshake(Handshake):
    def __init__(self, host, base, request):
        super().__init__(host, base)
        self.request, self.copies = request, 0

    def __call__(self, argument):
        if type(argument) is not int or argument & 15 != 2:
            return super().__call__(argument)
        try:
            require(self.phase == 'admitted' and self.locked and argument & ~15 == self.low
                    and self.copies == 0, 'one copied snapshot inside admitted window')
            self.copies += 1
            return int(self.request.copied())
        except BaseException as error:
            if self.error is None:
                self.error = error
            return 0


def validate_request(values, base, low, high, mode, iteration):
    require(mode in MODES and type(values) is list and len(values) == 8
            and all(type(v) is int and 0 <= v < 1 << 64 for v in values), 'complete request report')
    status, snapshot, workspace, output, absorbed, cleared, exported, size = values
    regions = [(snapshot, 1072), (workspace, 1170), (output, 32)]
    require(all(low <= p and p + n <= high for p, n in regions), 'bounded request storage')
    require(all(p + n <= q or q + m <= p for i, (p, n) in enumerate(regions)
                for q, m in regions[i + 1:]), 'disjoint request storage')
    expected = STATUS[mode]
    length = len(Request(mode, iteration).message) if expected in (1, 2, 12) else 0
    require(status == expected and absorbed == length and cleared == 1 and size == 1170
            and exported == (32 if expected == 1 else 0), 'exact request/cleanup result')
    return [status, snapshot - base, workspace - base, output - base, absorbed, cleared, exported, size]


def exercise(api, host, image, mode):
    require(api.machine == '0x8664' and host.geometry() == (4096, 65536), 'native x64 geometry')
    base = api.create()
    initialized, trampoline, calls = False, None, []
    try:
        loaded, error = api.load(base, image)
        require(loaded, f'request image load failed: {error}')
        count = api.initialize_worker(base)
        initialized = True
        require(count == 1, 'one synchronous request worker')
        def export(name):
            return api.check(api.GetProcAddress(base, name.encode()), name)
        routine, window = export('PublicRequest'), export('PublicLockedWindow')
        register, control, guards = export('PublicLockedHost'), export('PublicRequestControl'), export('PublicGuardControl')
        require(api.call(routine, 0) == api.call(control, 999) == 0, 'unregistered/unknown rejection')
        for iteration in range(3):
            request = Request(mode, iteration)
            handshake = RequestHandshake(host, base, request)
            trampoline = previous.callback(handshake)
            require(api.call(register, c.cast(trampoline, c.c_void_p).value) == 1, 'register callback')
            values = [api.call(routine, request.source)] + [api.call(window, op) for op in range(2, 9)]
            protection = [api.call(guards, op) for op in range(16, 29)]
            report = [api.call(control, op) for op in range(16, 24)]
            if handshake.error:
                raise handshake.error
            item = validate(values, base, False, False, False, handshake.trace, handshake.snapshots, handshake.locked)
            item['guards'] = previous.guard.validate_guards(protection, base, values[1], values[2], 'normal', False)
            item['request'] = validate_request(report, base, values[1], values[2], mode, iteration)
            item['restricted'] = api.call(control, 24)
            item['copies'] = handshake.copies
            require(item['restricted'] == 1 and item['copies'] == int(mode != 'bad-source'),
                    'restricted access and exact snapshot hook count')
            item['digest'] = request.check_output()
            calls.append(item)
            require(api.call(register, 0) == 1 and api.call(routine, 0) == 0, 'unregister callback')
    finally:
        try:
            if initialized:
                api.terminate(base)
        finally:
            api.delete(base)
    return {**dict.fromkeys(previous.guard.NONCLAIMS, False), 'synthetic_only': True,
            'deleted': True, 'native_machine': api.machine, 'mode': mode, 'calls': calls}


def bounded_child(command, mode):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 32768,
            f'request child failed/inconclusive: exit={result.returncode} '
            f'(0x{result.returncode & 0xffffffff:08x}); ' + result.stderr[-4096:])
    value = json.loads(result.stdout)
    require(type(value) is dict and all(value.get(name) is False for name in previous.guard.NONCLAIMS)
            and value.get('synthetic_only') is True and value.get('deleted') is True
            and value.get('native_machine') == '0x8664' and value.get('mode') == mode,
            'nonqualifying request record')
    calls = value.get('calls')
    require(type(calls) is list and len(calls) == 3, 'three complete request repetitions')
    for iteration, call in enumerate(calls):
        require(type(call) is dict, 'request call record')
        values = call.get('values', [])
        checked = validate(values, 0, False, False, False, call.get('trace'),
                           call.get('snapshots'), call.get('locked_until_teardown'))
        checked['guards'] = previous.guard.validate_guards(call.get('guards', []), 0, values[1], values[2], 'normal', False)
        checked['request'] = validate_request(call.get('request', []), 0, values[1], values[2], mode, iteration)
        checked['restricted'], checked['copies'] = 1, int(mode != 'bad-source')
        checked['digest'] = (hashlib.sha256(Request(mode, iteration).message).hexdigest()
                             if STATUS[mode] == 1 else None)
        require(checked == call and call['page_count'] == 16, 'canonical complete request record')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('mode', choices=MODES)
    parser.add_argument('--rust-archive', required=True, type=Path)
    parser.add_argument('--rustc-info', required=True, type=Path)
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    image, archive, identity = (p.resolve(strict=True) for p in (args.image, args.rust_archive, args.rustc_info))
    require(image.suffix.lower() == '.dll' and 0 < image.stat().st_size <= 4 * 1024 * 1024, 'bounded image')
    require(0 < archive.stat().st_size <= 4 * 1024 * 1024 and 0 < identity.stat().st_size <= 8192, 'bounded Rust artifacts')
    compiler = identity.read_text().strip()
    require(compiler.startswith('rustc 1.98.1 ') and 'LLVM version:' in compiler, 'pinned compiler')
    if args.child:
        print(json.dumps(exercise(WorkerNative(), Windows(), image, args.mode)))
        return
    root = Path(__file__).resolve().parents[2]
    def clean():
        require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'clean checkout required')
    def hashes():
        return {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in SOURCES}
    def artifacts():
        return {k: hashlib.sha256(p.read_bytes()).hexdigest() for k, p in
                (('image_sha256', image), ('rust_archive_sha256', archive), ('rustc_info_sha256', identity))}
    clean()
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    before, artifact_hashes = hashes(), artifacts()
    result = bounded_child([sys.executable, str(Path(__file__).resolve()), str(image), args.mode,
                            '--rust-archive', str(archive), '--rustc-info', str(identity), '--child'], args.mode)
    require(before == hashes() and artifact_hashes == artifacts(), 'source/artifact changed')
    require(commit == subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(), 'HEAD changed')
    clean()
    result.update(schema=1, kind='windows-enclave-public-request-experiment', status='OBSERVATIONS_ONLY',
                  commit=commit, source_sha256=before, rustc=compiler, rust_target='x86_64-pc-windows-msvc',
                  rust_panic='abort', **artifact_hashes, os=sys.getwindowsversion().build)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
