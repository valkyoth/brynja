#!/usr/bin/env python3
"""Fixed-frame depth/headroom experiment. No arbitrary-stack qualification."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import windows_enclave_window_guard as guard
from windows_enclave_worker import WorkerNative
from windows_enclave_window_lock import Handshake, validate
from windows_protection_api import Windows
from windows_protection_probe import require

SOURCES = guard.SOURCES + ('assurance/windows-enclave-probe/window_depth.c',
          'assurance/windows-enclave-probe/window_depth_x64.asm',
          'scripts/cryptography/windows_enclave_window_depth.py',
          'scripts/cryptography/test-windows-enclave-window-depth.py')


def validate_depth(values, base, low, high, depth, bounded, unwind, rejection):
    require(type(depth) is int and 0 <= depth <= 32 and len(values) == 10
            and all(type(v) is int and 0 <= v < 1 << 64 for v in values), 'complete bounded depth observation')
    visits, first, minimum, rejected_frame, rejects, leaves, caught, result, broken, local = values
    require(1 <= visits <= depth + 1 and low <= minimum <= first <= high - 4096
            and first % 16 == minimum % 16 == 0 and first - minimum == (visits - 1) * 4112,
            'exact descending frame population')
    require(broken == 0 and caught == int(unwind) and rejects == int(rejection)
            and leaves == int(not rejection) and result == (3 if unwind else (2 if rejection else 1)),
            'exact leaf/rejection/unwind outcome')
    require(low <= local < minimum + 4096, 'stop helper stays in payload')
    if bounded:
        require(minimum >= low + 16384, 'four-page frame headroom retained')
    if rejection:
        require(bounded and visits < depth + 1 and rejected_frame == minimum - 16
                and rejected_frame >= low + 16384 and rejected_frame - 4096 < low + 16384,
                'reject exactly the next frame at the budget boundary')
    else:
        require(visits == depth + 1 and rejected_frame == 0, 'complete requested depth')
    relative = values.copy()
    for index in (1, 2, 3, 9):
        if relative[index]:
            relative[index] -= base
    return relative


def callback(function):
    return c.WINFUNCTYPE(c.c_void_p, c.c_void_p)(function)


def exercise(api, host, image, depth, bounded, unwind, rejection):
    require(type(depth) is int and 0 <= depth <= 32 and (bounded or not rejection), 'fixed bounded probe request')
    require(api.machine == '0x8664' and host.geometry() == (4096, 65536), 'native x64 geometry')
    base = api.create()
    initialized, trampoline = False, None
    calls = []
    try:
        loaded, error = api.load(base, image)
        require(loaded, f'depth image load failed: {error}')
        count = api.initialize_worker(base)
        initialized = True
        require(count == 1, 'one synchronous depth worker')
        routine = api.check(api.GetProcAddress(base, b'PublicLockedWindow'), 'window export')
        register = api.check(api.GetProcAddress(base, b'PublicLockedHost'), 'callback export')
        control = api.check(api.GetProcAddress(base, b'PublicDepthControl'), 'depth export')
        guards = api.check(api.GetProcAddress(base, b'PublicGuardControl'), 'guard export')
        require(api.call(routine, 0) == 0 and api.call(control, 999) == 0, 'unknown/unregistered rejection')
        for _ in range(3):
            handshake = Handshake(host, base)
            trampoline = callback(handshake)
            require(api.call(control, depth | (256 if bounded else 0)) == 1, 'select depth')
            require(api.call(register, c.cast(trampoline, c.c_void_p).value) == 1, 'register callback')
            values = [api.call(routine, int(unwind))]
            values.extend(api.call(routine, op) for op in range(2, 9))
            protection = [api.call(guards, op) for op in range(16, 29)]
            frames = [api.call(control, op) for op in range(512, 522)]
            if handshake.error is not None:
                raise handshake.error
            item = validate(values, base, unwind, False, False,
                            handshake.trace, handshake.snapshots, handshake.locked)
            item['guards'] = guard.validate_guards(protection, base, values[1], values[2], 'normal', False)
            item['depth'] = validate_depth(frames, base, values[1], values[2], depth, bounded, unwind, rejection)
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
            'native_machine': api.machine, 'unwind': unwind, 'bounded': bounded,
            'rejection': rejection, 'requested_depth': depth, 'calls': calls}


def bounded_child(command, depth, bounded, unwind, rejection):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 32768,
            f'depth child failed/inconclusive: exit={result.returncode} '
            f'(0x{result.returncode & 0xffffffff:08x}); ' + result.stderr[-4096:])
    value = json.loads(result.stdout)
    require(type(value) is dict and all(value.get(name) is False for name in guard.NONCLAIMS)
            and value.get('synthetic_only') is True and value.get('deleted') is True
            and value.get('native_machine') == '0x8664' and value.get('unwind') is unwind
            and value.get('bounded') is bounded and value.get('rejection') is rejection
            and type(value.get('requested_depth')) is int and value['requested_depth'] == depth,
            'nonqualifying exact depth mode')
    calls = value.get('calls')
    require(type(calls) is list and len(calls) == 3, 'three complete depth repetitions')
    for call in calls:
        require(type(call) is dict, 'call record')
        values = call.get('values', [])
        checked = validate(values, 0, unwind, False, False,
                           call.get('trace'), call.get('snapshots'), call.get('locked_until_teardown'))
        checked['guards'] = guard.validate_guards(call.get('guards', []), 0, values[1], values[2], 'normal', False)
        checked['depth'] = validate_depth(call.get('depth', []), 0, values[1], values[2], depth, bounded, unwind, rejection)
        require(checked == call and call['page_count'] == 16, 'complete canonical depth record')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('depth', type=int, choices=range(33))
    parser.add_argument('--unchecked', action='store_true')
    parser.add_argument('--unwind', action='store_true')
    parser.add_argument('--expect-rejection', action='store_true')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    require(image.suffix.lower() == '.dll' and 0 < image.stat().st_size <= 4 * 1024 * 1024, 'bounded image')
    if args.child:
        print(json.dumps(exercise(WorkerNative(), Windows(), image, args.depth, not args.unchecked,
                                 args.unwind, args.expect_rejection)))
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
    command = [sys.executable, str(source), str(image), str(args.depth), '--child']
    for flag, enabled in (('--unchecked', args.unchecked), ('--unwind', args.unwind),
                          ('--expect-rejection', args.expect_rejection)):
        if enabled:
            command.append(flag)
    record = bounded_child(command, args.depth, not args.unchecked, args.unwind, args.expect_rejection)
    require(before == hashes() and image_hash == hashlib.sha256(image.read_bytes()).hexdigest(), 'source/image changed')
    require(commit == subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(), 'HEAD changed')
    clean()
    record.update(schema=1, kind='windows-enclave-stack-depth-experiment', status='OBSERVATIONS_ONLY',
                  commit=commit, source_sha256=before, image_sha256=image_hash, os=sys.getwindowsversion().build)
    print(json.dumps(record, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
