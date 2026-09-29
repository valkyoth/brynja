#!/usr/bin/env python3
"""Scoped public-result wire experiment; no confidential channel or qualification."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import windows_enclave_hardened as previous
import windows_enclave_wire_build as build
from windows_enclave_worker import WorkerNative
from windows_enclave_window_lock import validate
from windows_protection_api import Windows
from windows_protection_probe import require
from windows_enclave_wire_cases import (
    MODES, Request, WireHandshake, message, outcome, validate_report, validate_offers)

SOURCES = tuple(dict.fromkeys(previous.SOURCES + build.SOURCES + (
    'scripts/cryptography/windows_enclave_wire.py',
    'scripts/cryptography/windows_enclave_wire_cases.py',
    'scripts/cryptography/test-windows-enclave-wire-native.py')))


def exercise(api, host, image, mode, foreign=None):
    require(api.machine == '0x8664' and host.geometry() == (4096, 65536), 'native x64 geometry')
    donor = exercise(api, host, image, 'publish') if mode == 'cross-instance' else None
    if donor:
        foreign = donor['calls'][0]['offers'][0][:4]
    base = api.create()
    initialized, trampoline, calls, last = False, None, [], None
    try:
        loaded, error = api.load(base, image)
        require(loaded, f'wire image load failed: {error}')
        count = api.initialize_worker(base)
        initialized = True
        require(count == 1, 'one synchronous wire worker')
        def export(name):
            return api.check(api.GetProcAddress(base, name.encode()), name)
        routine, window = export('PublicWire'), export('PublicLockedWindow')
        register, control, guards = export('PublicLockedHost'), export('PublicWireControl'), export('PublicGuardControl')
        require(api.call(routine, 0) == api.call(control, 999) == 0, 'unregistered/unknown rejection')
        for iteration in range(3):
            request = Request(mode, iteration, last, foreign)
            handshake = WireHandshake(host, base, request)
            trampoline = previous.callback(handshake)
            require(api.call(register, c.cast(trampoline, c.c_void_p).value) == 1, 'register callback')
            values = [api.call(routine, request.source)] + [api.call(window, op) for op in range(2, 9)]
            protection = [api.call(guards, op) for op in range(16, 29)]
            report = [api.call(control, op) for op in range(16, 24)]
            if handshake.error:
                raise handshake.error
            item = validate(values, base, False, False, False, handshake.trace, handshake.snapshots, handshake.locked)
            item['guards'] = previous.guard.validate_guards(protection, base, values[1], values[2], 'normal', False)
            item['wire'] = validate_report(report, base, values[1], values[2], mode, iteration)
            item['restricted'] = api.call(control, 24)
            require(item['restricted'] == 1, 'restricted wire access')
            item['offers'] = request.offers
            last = validate_offers(request.offers, mode, iteration, last)
            if donor and last:
                require(last[:2] != foreign[:2], 'independent new instance namespace')
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
            'deleted': True, 'native_machine': api.machine, 'mode': mode, 'calls': calls, 'donor': donor}


def validate_record(value, mode):
    require(type(value) is dict and all(value.get(name) is False for name in previous.guard.NONCLAIMS)
            and value.get('synthetic_only') is True and value.get('deleted') is True
            and value.get('native_machine') == '0x8664' and value.get('mode') == mode,
            'nonqualifying wire record')
    calls = value.get('calls')
    require(type(calls) is list and len(calls) == 3, 'three complete wire repetitions')
    donor = value.get('donor')
    if mode == 'cross-instance':
        validate_record(donor, 'publish')
    else:
        require(donor is None, 'no unexpected donor')
    last = None
    for iteration, call in enumerate(calls):
        require(type(call) is dict, 'wire call record')
        values = call.get('values', [])
        checked = validate(values, 0, False, False, False, call.get('trace'),
                           call.get('snapshots'), call.get('locked_until_teardown'))
        checked['guards'] = previous.guard.validate_guards(call.get('guards', []), 0, values[1], values[2], 'normal', False)
        checked['wire'] = validate_report(call.get('wire', []), 0, values[1], values[2], mode, iteration)
        checked['restricted'] = 1
        checked['offers'] = call.get('offers')
        last = validate_offers(checked['offers'], mode, iteration, last)
        if donor:
            require(last[:2] != donor['calls'][0]['offers'][0][:2], 'distinct donor namespace')
        checked['digest'] = (hashlib.sha256(message(mode, iteration)).hexdigest()
                             if outcome(mode, iteration)[0] == 1 else None)
        require(checked == call and call['page_count'] == 16, 'canonical complete wire record')
    expected = {**dict.fromkeys(previous.guard.NONCLAIMS, False), 'synthetic_only': True,
                'deleted': True, 'native_machine': '0x8664', 'mode': mode, 'calls': calls, 'donor': donor}
    require(expected == value, 'canonical wire envelope')
    return value


def bounded_child(command, mode):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 32768,
            f'wire child failed/inconclusive: exit={result.returncode} '
            f'(0x{result.returncode & 0xffffffff:08x}); ' + result.stderr[-4096:])
    return validate_record(json.loads(result.stdout), mode)

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
    result.update(schema=1, kind='windows-enclave-scoped-wire-experiment', status='OBSERVATIONS_ONLY',
                  commit=commit, source_sha256=before, rustc=compiler, rust_target='x86_64-pc-windows-msvc',
                  rust_panic='abort', **artifact_hashes, os=sys.getwindowsversion().build)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()

