#!/usr/bin/env python3
"""Existing portable SHA-256 public vectors; no secret or unwind qualification."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import windows_enclave_window_guard as guard
import windows_enclave_sha256_build as build
from windows_enclave_worker import WorkerNative
from windows_enclave_window_lock import Handshake, validate
from windows_protection_api import Windows
from windows_protection_probe import require

SOURCES = guard.SOURCES + ('assurance/windows-enclave-probe/window_rust.c',
          'assurance/windows-enclave-probe/window_sha256.c',
          'assurance/windows-enclave-probe/window_sha256.rs',
          'assurance/windows-enclave-probe/sha256_vectors.rs',
          'scripts/cryptography/windows_enclave_sha256_build.py',
          'assurance/windows-enclave-probe/window_rust_x64.asm',
          'scripts/cryptography/windows_enclave_sha256.py',
          'scripts/cryptography/test-windows-enclave-sha256.py') + tuple(build.source_files())


MODES = {'success': 0, 'cancel': 1, 'reject': 2, 'error': 3}


def validate_sha256(values, base, low, high, mode, mutant):
    require(mode in MODES and type(values) is list and len(values) == 4
            and all(type(v) is int and 0 <= v < 1 << 64 for v in values),
            'complete Rust report')
    status, address, comparisons, cleared = values
    require(not (mutant and mode == 'reject'), 'missing-clear control requires writes')
    require(low <= address <= high - 1024, 'complete Rust local array in locked window')
    require(status == (0 if mutant else MODES[mode] + 1)
            and comparisons == {'success': 40, 'cancel': 20, 'reject': 0, 'error': 40}[mode]
            and cleared == int(not mutant), 'exact SHA-256 outcome and local clearing')
    return [status, address - base, comparisons, cleared]


def callback(function):
    return c.WINFUNCTYPE(c.c_void_p, c.c_void_p)(function)


def exercise(api, host, image, mode, unwind, mutant):
    require(mode in MODES and not (mutant and mode == 'reject'), 'fixed Rust probe request')
    require(api.machine == '0x8664' and host.geometry() == (4096, 65536), 'native x64 geometry')
    base = api.create()
    initialized, trampoline = False, None
    calls = []
    try:
        loaded, error = api.load(base, image)
        require(loaded, f'Rust image load failed: {error}')
        count = api.initialize_worker(base)
        initialized = True
        require(count == 1, 'one synchronous Rust worker')
        routine = api.check(api.GetProcAddress(base, b'PublicLockedWindow'), 'window export')
        register = api.check(api.GetProcAddress(base, b'PublicLockedHost'), 'callback export')
        control = api.check(api.GetProcAddress(base, b'PublicRustControl'), 'Rust export')
        guards = api.check(api.GetProcAddress(base, b'PublicGuardControl'), 'guard export')
        require(api.call(routine, 0) == 0 and api.call(control, 999) == 0, 'unknown/unregistered rejection')
        for _ in range(3):
            handshake = Handshake(host, base)
            trampoline = callback(handshake)
            require(api.call(control, MODES[mode]) == 1, 'select Rust mode')
            require(api.call(register, c.cast(trampoline, c.c_void_p).value) == 1, 'register callback')
            values = [api.call(routine, int(unwind))]
            values.extend(api.call(routine, op) for op in range(2, 9))
            protection = [api.call(guards, op) for op in range(16, 29)]
            report = [api.call(control, op) for op in range(16, 20)]
            if handshake.error is not None:
                raise handshake.error
            item = validate(values, base, unwind, False, False,
                            handshake.trace, handshake.snapshots, handshake.locked)
            item['guards'] = guard.validate_guards(protection, base, values[1], values[2], 'normal', False)
            item['sha256'] = validate_sha256(report, base, values[1], values[2], mode, mutant)
            require(item['page_count'] == 16, 'sixteen payload pages')
            calls.append(item)
            require(api.call(register, 0) == 1 and api.call(routine, 0) == 0, 'unregister callback')
    finally:
        try:
            if initialized:
                api.terminate(base)
        finally:
            api.delete(base)
    return {**dict.fromkeys(guard.NONCLAIMS, False), 'synthetic_only': True, 'deleted': True,
            'native_machine': api.machine, 'c_exception_before': unwind, 'mode': mode,
            'missing_local_clear_mutant': mutant, 'calls': calls}


def bounded_child(command, mode, unwind, mutant):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 32768,
            f'Rust child failed/inconclusive: exit={result.returncode} '
            f'(0x{result.returncode & 0xffffffff:08x}); ' + result.stderr[-4096:])
    value = json.loads(result.stdout)
    require(type(value) is dict and all(value.get(name) is False for name in guard.NONCLAIMS)
            and value.get('synthetic_only') is True and value.get('deleted') is True
            and value.get('native_machine') == '0x8664' and value.get('c_exception_before') is unwind
            and value.get('missing_local_clear_mutant') is mutant and value.get('mode') == mode,
            'nonqualifying exact Rust mode')
    calls = value.get('calls')
    require(type(calls) is list and len(calls) == 3, 'three complete Rust repetitions')
    for call in calls:
        require(type(call) is dict, 'call record')
        values = call.get('values', [])
        checked = validate(values, 0, unwind, False, False,
                           call.get('trace'), call.get('snapshots'), call.get('locked_until_teardown'))
        checked['guards'] = guard.validate_guards(call.get('guards', []), 0, values[1], values[2], 'normal', False)
        checked['sha256'] = validate_sha256(call.get('sha256', []), 0, values[1], values[2], mode, mutant)
        require(checked == call and call['page_count'] == 16, 'complete canonical Rust record')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('mode', choices=MODES)
    parser.add_argument('--rust-archive', type=Path, required=True)
    parser.add_argument('--rustc-info', type=Path, required=True)
    parser.add_argument('--c-exception-before', action='store_true')
    parser.add_argument('--missing-local-clear-mutant', action='store_true')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    obj = args.rust_archive.resolve(strict=True)
    identity = args.rustc_info.resolve(strict=True)
    require(image.suffix.lower() == '.dll' and 0 < image.stat().st_size <= 4 * 1024 * 1024, 'bounded image')
    require(0 < obj.stat().st_size <= 4 * 1024 * 1024 and 0 < identity.stat().st_size <= 8192, 'bounded Rust artifacts')
    compiler = identity.read_text().strip()
    require(compiler.startswith('rustc 1.98.1 ') and 'LLVM version:' in compiler, 'pinned experiment compiler')
    if args.child:
        print(json.dumps(exercise(WorkerNative(), Windows(), image, args.mode,
                                 args.c_exception_before, args.missing_local_clear_mutant)))
        return
    source = Path(__file__).resolve()
    root = source.parents[2]
    def clean():
        require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'clean checkout required')
    def hashes():
        return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCES}
    def artifacts():
        return {name: hashlib.sha256(path.read_bytes()).hexdigest()
                for name, path in (('image_sha256', image), ('rust_archive_sha256', obj), ('rustc_info_sha256', identity))}
    clean()
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    before, artifact_hashes = hashes(), artifacts()
    command = [sys.executable, str(source), str(image), args.mode, '--rust-archive', str(obj),
               '--rustc-info', str(identity), '--child']
    for flag, enabled in (('--c-exception-before', args.c_exception_before),
                          ('--missing-local-clear-mutant', args.missing_local_clear_mutant)):
        if enabled:
            command.append(flag)
    record = bounded_child(command, args.mode, args.c_exception_before, args.missing_local_clear_mutant)
    require(before == hashes() and artifact_hashes == artifacts(), 'source/artifact changed')
    require(commit == subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(), 'HEAD changed')
    clean()
    record.update(schema=1, kind='windows-enclave-sha256-public-vector-experiment', status='OBSERVATIONS_ONLY',
                  commit=commit, source_sha256=before, rustc=compiler, rust_target='x86_64-pc-windows-msvc',
                  rust_panic='abort', **artifact_hashes, os=sys.getwindowsversion().build)
    print(json.dumps(record, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
