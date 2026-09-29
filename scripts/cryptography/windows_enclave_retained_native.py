#!/usr/bin/env python3
"""Fixed PUBLIC-vector retained Rust-owner experiment, not Windows strict support."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import windows_enclave_persistent as storage
from windows_enclave_sha256_build import vectors
from windows_protection_probe import require


def campaign():
    steps = [(0, 1, True, None)]
    for case in range(20):
        steps += [(1 | (case << 8), 2, True, None), (2, 3, True, case), (2, 102, True, None)]
    steps += [(257, 2, True, None), (1, 101, True, None), (4, 5, True, None), (2, 102, True, None),
              (257, 2, True, None), (5, 103, True, None), (2, 102, True, None),
              (257, 2, True, None), (6, 105, True, None), (1, 107, True, None), (2, 107, True, None),
              (3, 4, False, None), (0, 1, True, None), (257, 2, True, None), (7, 6, True, None),
              (2, 107, True, None), (3, 4, False, None), (0, 1, True, None),
              (257, 2, True, None), (3, 4, False, None), (2, 102, False, None)]
    return steps


def check_report(report, step, deny=False):
    operation, status, live, _ = step
    require(type(report) is list and len(report) == 10 and
            all(type(v) is int and 0 <= v < 1 << 64 for v in report), 'complete retained Rust report')
    absent = operation == 2 and not live
    region, data = report[1:3]
    if absent:
        require(region == data == 0, 'no stale released page')
    else:
        require(region % 4096 == 0 and 0 <= region < data == region + 4096 and
                region + 12288 <= storage.LIMIT, 'retained page geometry')
    expected = [status, region, data, int(live), int(operation & 255 == 1),
                4096 if operation == 3 else 0, int(deny or operation == 3), 0, 1, operation]
    require(report == expected, f'exact retained Rust outcome: {report} expected {expected}')


def check_record(record, deny):
    require(type(record) is dict and set(record) == set(storage.guard.NONCLAIMS) |
            {'synthetic_only', 'deleted', 'native_machine', 'denied', 'calls', 'events'}, 'canonical record')
    require(all(record[k] is False for k in storage.guard.NONCLAIMS) and record['synthetic_only'] is True
            and record['deleted'] is True and record['native_machine'] == '0x8664'
            and record['denied'] is deny, 'nonqualifying claims')
    steps = [(0, 111, False, None)] if deny else campaign()
    require(type(record['calls']) is list and len(record['calls']) == len(steps), 'complete campaign')
    expected_events, previous = [], None
    for call, step in zip(record['calls'], steps):
        values = call.get('values', [])
        checked = storage.validate(values, 0, False, False, False, call.get('trace'),
                                   call.get('snapshots'), call.get('locked_until_teardown'))
        checked['guards'] = storage.guard.validate_guards(call.get('guards', []), 0, values[1], values[2], 'normal', False)
        report = call.get('retained')
        check_report(report, step, deny)
        checked['retained'] = report
        operation, _, live, case = step
        region, data = report[1:3]
        if region:
            require(region + 12288 <= values[1] - 4096 or region >= values[2] + 4096, 'page outside worker guards')
        if operation == 0:
            previous = region
            expected_events.append(('deny' if deny else 'lock', data))
        elif region:
            require(region == previous, 'stable owner placement across worker returns')
            expected_events.append(('check', data))
            if operation == 3:
                expected_events += [('clear', data), ('unlock', data)]
        flags = call.get('retained_flags')
        if live:
            storage.flags_check(flags, 4096, True)
        else:
            require(flags == [], 'no released residency claim')
        checked['retained_flags'] = flags
        expected_output = hashlib.sha256(vectors()[case]).hexdigest() if case is not None else 'cc' * 32
        require(call.get('output') == expected_output, 'independent retained digest or untouched destination')
        checked['output'] = expected_output
        require(checked == call, 'canonical complete native call')
    events = record['events']
    require(type(events) is list and len(events) == len(expected_events), 'all residency events')
    for event, (name, offset) in zip(events, expected_events):
        keys = {'event', 'offset'} | ({'before', 'locked'} if name == 'lock' else
                                    {'locked'} if name in ('check', 'clear') else set())
        require(set(event) == keys and event['event'] == name and event['offset'] == offset, 'bound residency event')
        if name == 'lock':
            storage.flags_check(event['before'], 4096, False)
        if 'locked' in event:
            storage.flags_check(event['locked'], 4096, True)
    return record


def exercise(api, host, image, deny):
    require(api.machine == '0x8664' and host.geometry() == (4096, 65536), 'native geometry')
    base = api.create()
    initialized, calls = False, []
    resident = storage.Retained(host, base, deny)
    output = (c.c_ubyte * 32)()
    try:
        loaded, error = api.load(base, image)
        require(loaded, f'image load: {error}')
        count = api.initialize_worker(base)
        initialized = True
        require(count == 1, 'one serialized enclave thread')
        def export(name):
            return api.check(api.GetProcAddress(base, name.encode()), name)
        routine, window = export('PublicRetained'), export('PublicLockedWindow')
        register, control = export('PublicLockedHost'), export('PublicRetainedControl')
        out_register, guards = export('PublicRetainedOutput'), export('PublicGuardControl')
        require(api.call(routine, 0) == api.call(control, 999) == 0, 'unregistered/unknown rejection')
        require(api.call(out_register, c.addressof(output)) == 1, 'public destination registration')
        for step in ([(0, 111, False, None)] if deny else campaign()):
            operation = step[0]
            c.memset(output, 0xcc, 32)
            resident.window = storage.Handshake(host, base)
            trampoline = storage.guard.callback(resident)
            require(api.call(register, c.cast(trampoline, c.c_void_p).value) == 1, 'register')
            values = [api.call(routine, operation)] + [api.call(window, op) for op in range(2, 9)]
            report = [api.call(control, op) for op in range(16, 26)]
            if resident.error or resident.window.error:
                raise RuntimeError(f'retained callback failed: {report}') from (resident.error or resident.window.error)
            item = storage.validate(values, base, False, False, False, resident.window.trace,
                                    resident.window.snapshots, resident.window.locked)
            item['guards'] = storage.guard.validate_guards([api.call(guards, op) for op in range(16, 29)],
                                                         base, values[1], values[2], 'normal', False)
            report[1:3] = [value - base if value else 0 for value in report[1:3]]
            check_report(report, step, deny)
            item['retained'] = report
            item['retained_flags'] = resident.snapshot() if resident.locked else []
            item['output'] = bytes(output).hex()
            calls.append(item)
            require(api.call(register, 0) == 1 and api.call(routine, 0) == 0, 'unregister')
        require(not resident.locked, 'all retained pages released')
    finally:
        try:
            if initialized:
                api.terminate(base)
        finally:
            api.delete(base)
    return check_record({**dict.fromkeys(storage.guard.NONCLAIMS, False), 'synthetic_only': True,
                         'deleted': True, 'native_machine': '0x8664', 'denied': deny,
                         'calls': calls, 'events': resident.events}, deny)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--deny', action='store_true')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    require(image.suffix.lower() == '.dll' and 0 < image.stat().st_size <= 4 * 1024 * 1024, 'bounded image')
    if args.child:
        print(json.dumps(exercise(storage.WorkerNative(), storage.Windows(), image, args.deny)))
        return
    from windows_enclave_retained_worker_build import SOURCES, base
    root = base.ROOT
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'clean checkout')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    hashes = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in SOURCES}
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    result = subprocess.run([sys.executable, __file__, str(image), '--child'] + (['--deny'] if args.deny else []),
                            capture_output=True, text=True, timeout=90)
    require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 2 * 1024 * 1024,
            f'native retained child failed ({result.returncode}): {result.stderr[-6000:]}')
    record = check_record(json.loads(result.stdout), args.deny)
    require(digest == hashlib.sha256(image.read_bytes()).hexdigest() and
            hashes == {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in SOURCES}, 'unchanged sources/image')
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root) and
            commit == subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(), 'unchanged checkout')
    record.update(schema=1, kind='windows-enclave-retained-rust-experiment', status='OBSERVATIONS_ONLY',
                  commit=commit, source_sha256=hashes, image_sha256=digest, os=sys.getwindowsversion().build)
    print(json.dumps(record, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
