#!/usr/bin/env python3
"""Bounded synthetic native stack-window handshake; NOT strict qualification."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from windows_enclave_worker import WorkerNative
from windows_enclave_window_lock import Handshake, validate, FAULTS
from windows_protection_api import Windows
from windows_protection_probe import require

NONCLAIMS = ('strict_qualified', 'production_signed', 'rust_unwind_qualified',
             'dump_exclusion_verified', 'guard_bounds_verified', 'full_worker_cleanup_proved',
             'malicious_host_residency_attestation')
SOURCES = ('assurance/windows-enclave-probe/synthetic.c',
           'assurance/windows-enclave-probe/window_lock.c',
           'assurance/windows-enclave-probe/window_lock_x64.asm',
           'scripts/cryptography/check-windows-enclave-window-lock.py',
           'scripts/cryptography/windows_enclave_window_lock.py',
           'scripts/cryptography/test-windows-enclave-window-lock.py',
           'scripts/cryptography/windows_enclave_worker.py',
           'scripts/cryptography/windows_enclave_lifecycle.py',
           'scripts/cryptography/windows_protection_api.py',
           'scripts/cryptography/windows_protection_probe.py')


def callback(function):
    return c.WINFUNCTYPE(c.c_void_p, c.c_void_p)(function)


def exercise(api, host, image, unwind=False, mutant=False, deny=False, fault=None):
    require(api.machine == '0x8664' and host.geometry() == (4096, 65536), 'native x64 geometry')
    require(not (mutant and (deny or fault)), 'distinct mutant and denial/fault controls')
    base = api.create()
    initialized, trampoline = False, None
    calls = []
    try:
        loaded, error = api.load(base, image)
        require(loaded, f'locked-window image load failed: {error}')
        count = api.initialize_worker(base)
        initialized = True
        require(count == 1, 'exactly one synchronous worker required')
        routine = api.check(api.GetProcAddress(base, b'PublicLockedWindow'), 'window export')
        register = api.check(api.GetProcAddress(base, b'PublicLockedHost'), 'callback export')
        require(api.call(routine, 0) == 0 and api.call(routine, 99) == 0,
                'unregistered/unknown operation must reject')
        for _ in range(1 if mutant else 3):
            handshake = Handshake(host, base, deny, fault)
            # Keep the callback strongly referenced through termination, even on error.
            trampoline = callback(handshake)
            address = c.cast(trampoline, c.c_void_p).value
            require(api.call(register, address) == 1, 'register public synthetic callback')
            values = [api.call(routine, int(unwind))]
            values.extend(api.call(routine, op) for op in range(2, 9))
            if handshake.error is not None:
                raise handshake.error
            calls.append(validate(values, base, unwind, mutant, deny,
                                  handshake.trace, handshake.snapshots, handshake.locked))
            require(api.call(register, 0) == 1 and api.call(routine, 0) == 0,
                    'unregister callback and reject further execution')
    finally:
        try:
            if initialized:
                api.terminate(base)
        finally:
            api.delete(base)
    return {**dict.fromkeys(NONCLAIMS, False), 'synthetic_only': True, 'deleted': True,
            'native_machine': api.machine, 'unwind': unwind, 'missing_clear_mutant': mutant,
            'denied': deny, 'calls': calls}


def bounded(command, unwind, mutant, deny):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 32768,
            f'window-lock child failed/inconclusive: exit={result.returncode}; ' + result.stderr[-4096:])
    value = json.loads(result.stdout)
    require(type(value) is dict and all(value.get(name) is False for name in NONCLAIMS)
            and value.get('synthetic_only') is True and value.get('deleted') is True
            and value.get('native_machine') == '0x8664' and value.get('unwind') is unwind
            and value.get('missing_clear_mutant') is mutant and value.get('denied') is deny,
            'exact nonqualifying live-window mode')
    calls = value.get('calls')
    require(type(calls) is list and len(calls) == (1 if mutant else 3), 'complete call observations')
    for call in calls:
        require(type(call) is dict, 'call record required')
        checked = validate(call.get('values', []), 0, unwind, mutant, deny,
                           call.get('trace'), call.get('snapshots'), call.get('locked_until_teardown'))
        require(call == checked, 'canonical complete live-window record')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--unwind', action='store_true')
    parser.add_argument('--missing-clear-mutant', action='store_true')
    parser.add_argument('--deny', action='store_true')
    parser.add_argument('--fault', choices=FAULTS)
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    require(image.suffix.lower() == '.dll' and 0 < image.stat().st_size <= 4 * 1024 * 1024,
            'bounded synthetic image')
    if args.child:
        print(json.dumps(exercise(WorkerNative(), Windows(), image, args.unwind,
                                 args.missing_clear_mutant, args.deny, args.fault)))
        return
    source = Path(__file__).resolve()
    root = source.parents[2]
    def clean():
        require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root),
                'clean checkout required')
    def hashes():
        return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCES}
    clean()
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    before, image_hash = hashes(), hashlib.sha256(image.read_bytes()).hexdigest()
    command = [sys.executable, str(source), str(image), '--child', *sys.argv[2:]]
    record = bounded(command, args.unwind, args.missing_clear_mutant, args.deny)
    require(not args.fault, 'injected callback fault must fail, never become an observation pass')
    require(before == hashes() and image_hash == hashlib.sha256(image.read_bytes()).hexdigest(),
            'source/image changed')
    clean()
    record.update(schema=1, kind='windows-enclave-live-window-lock-experiment', status='OBSERVATIONS_ONLY',
                  commit=commit, source_sha256=before, image_sha256=image_hash,
                  os=sys.getwindowsversion().build)
    print(json.dumps(record, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
