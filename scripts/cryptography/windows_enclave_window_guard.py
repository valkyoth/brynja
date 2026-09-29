#!/usr/bin/env python3
"""Synthetic guarded window observations, not a production execution boundary."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from windows_enclave_worker import WorkerNative
from windows_enclave_window_lock import Handshake, validate
from windows_protection_api import Windows
from windows_protection_probe import require

MODES = {'normal': 0, 'read-low': 1, 'write-low': 2, 'read-high': 3, 'write-high': 4}
NONCLAIMS = ('strict_qualified', 'production_signed', 'rust_unwind_qualified',
             'dump_exclusion_verified', 'full_worker_cleanup_proved',
             'arbitrary_call_depth_qualified', 'malicious_host_residency_attestation')
SOURCES = ('assurance/windows-enclave-probe/synthetic.c',
           'assurance/windows-enclave-probe/window_lock.c',
           'assurance/windows-enclave-probe/window_guard.c',
           'assurance/windows-enclave-probe/window_guard_x64.asm',
           'scripts/cryptography/windows_enclave_window_guard.py',
           'scripts/cryptography/test-windows-enclave-window-guard.py',
           'scripts/cryptography/windows_enclave_window_lock.py',
           'scripts/cryptography/windows_enclave_worker.py',
           'scripts/cryptography/windows_enclave_lifecycle.py',
           'scripts/cryptography/windows_protection_api.py',
           'scripts/cryptography/windows_protection_probe.py')


def validate_guards(values, base, low, high, mode, deny):
    require(mode in MODES and len(values) == 13 and
            all(type(v) is int and 0 <= v < 1 << 64 for v in values), 'complete guard observation')
    require(low % 4096 == 0 and high - low == 65536 and base <= low - 4096
            and high + 4096 <= base + 0x10000000, 'independent page-aligned boundaries')
    active_probe = mode != 'normal' and not deny
    address = (low - 1 if mode.endswith('low') else high) if active_probe else 0
    expected = [low - 4096, high, 1, 1, 2 if active_probe else 0,
                int(active_probe), 0xc0000005 if active_probe else 0,
                int(active_probe and mode.startswith('write')), address, 0, 0, 0, 0]
    require(values == expected, 'exact persistent boundary-fault and restoration observations')
    result = values.copy()
    for index in (0, 1, 8):
        if result[index]:
            result[index] -= base
    return result


def callback(function):
    return c.WINFUNCTYPE(c.c_void_p, c.c_void_p)(function)


def exercise(api, host, image, mode, unwind=False, mutant=False, deny=False):
    require(api.machine == '0x8664' and host.geometry() == (4096, 65536), 'native x64 geometry')
    require(mode in MODES and not (deny and mutant), 'distinct known controls')
    base = api.create()
    initialized, trampoline = False, None
    calls = []
    try:
        loaded, error = api.load(base, image)
        require(loaded, f'guarded-window image load failed: {error}')
        count = api.initialize_worker(base)
        initialized = True
        require(count == 1, 'one synchronous guarded worker')
        routine = api.check(api.GetProcAddress(base, b'PublicLockedWindow'), 'window export')
        register = api.check(api.GetProcAddress(base, b'PublicLockedHost'), 'callback export')
        control = api.check(api.GetProcAddress(base, b'PublicGuardControl'), 'guard export')
        require(api.call(routine, 0) == 0 and api.call(control, 99) == 0, 'unknown/unregistered rejection')
        for _ in range(1 if mutant else 3):
            handshake = Handshake(host, base, deny)
            trampoline = callback(handshake)
            require(api.call(control, MODES[mode]) == 1, 'select fixed boundary probe')
            require(api.call(register, c.cast(trampoline, c.c_void_p).value) == 1, 'register callback')
            values = [api.call(routine, int(unwind))]
            values.extend(api.call(routine, op) for op in range(2, 9))
            guards = [api.call(control, op) for op in range(16, 29)]
            if handshake.error is not None:
                raise RuntimeError(f'guard handshake failed; values={values}; guards={guards}') from handshake.error
            item = validate(values, base, unwind, mutant, deny,
                            handshake.trace, handshake.snapshots, handshake.locked)
            item['guards'] = validate_guards(guards, base, values[1], values[2], mode, deny)
            require(item['page_count'] == 16, 'exactly sixteen payload pages')
            calls.append(item)
            require(api.call(register, 0) == 1 and api.call(routine, 0) == 0, 'unregister callback')
    finally:
        try:
            if initialized:
                api.terminate(base)
        finally:
            api.delete(base)
    return {**dict.fromkeys(NONCLAIMS, False), 'synthetic_only': True, 'deleted': True,
            'native_machine': api.machine, 'unwind': unwind, 'missing_clear_mutant': mutant,
            'denied': deny, 'mode': mode, 'calls': calls}


def bounded(command, mode, unwind, mutant, deny):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 32768,
            f'guard child failed/inconclusive: exit={result.returncode}; ' + result.stderr[-4096:])
    value = json.loads(result.stdout)
    require(type(value) is dict and all(value.get(name) is False for name in NONCLAIMS)
            and value.get('synthetic_only') is True and value.get('deleted') is True
            and value.get('native_machine') == '0x8664' and value.get('unwind') is unwind
            and value.get('missing_clear_mutant') is mutant and value.get('denied') is deny
            and value.get('mode') == mode, 'nonqualifying exact guard mode')
    calls = value.get('calls')
    require(type(calls) is list and len(calls) == (1 if mutant else 3), 'complete guard repetitions')
    for call in calls:
        require(type(call) is dict, 'call record')
        values = call.get('values', [])
        checked = validate(values, 0, unwind, mutant, deny,
                           call.get('trace'), call.get('snapshots'), call.get('locked_until_teardown'))
        checked['guards'] = validate_guards(call.get('guards', []), 0, values[1], values[2], mode, deny)
        require(checked == call and call['page_count'] == 16, 'canonical complete guard record')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('mode', choices=MODES)
    parser.add_argument('--unwind', action='store_true')
    parser.add_argument('--missing-clear-mutant', action='store_true')
    parser.add_argument('--deny', action='store_true')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    require(image.suffix.lower() == '.dll' and 0 < image.stat().st_size <= 4 * 1024 * 1024,
            'bounded synthetic image')
    if args.child:
        print(json.dumps(exercise(WorkerNative(), Windows(), image, args.mode, args.unwind,
                                 args.missing_clear_mutant, args.deny)))
        return
    source = Path(__file__).resolve()
    root = source.parents[2]
    def clean():
        require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'clean checkout required')
    def hashes():
        return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCES}
    clean()
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    before, image_hash = hashes(), hashlib.sha256(image.read_bytes()).hexdigest()
    command = [sys.executable, str(source), str(image), args.mode, '--child']
    for flag, enabled in (('--unwind', args.unwind), ('--missing-clear-mutant', args.missing_clear_mutant),
                          ('--deny', args.deny)):
        if enabled:
            command.append(flag)
    record = bounded(command, args.mode, args.unwind, args.missing_clear_mutant, args.deny)
    require(before == hashes() and image_hash == hashlib.sha256(image.read_bytes()).hexdigest(), 'source/image changed')
    require(commit == subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(), 'HEAD changed')
    clean()
    record.update(schema=1, kind='windows-enclave-guarded-window-experiment', status='OBSERVATIONS_ONLY',
                  commit=commit, source_sha256=before, image_sha256=image_hash,
                  os=sys.getwindowsversion().build)
    print(json.dumps(record, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
