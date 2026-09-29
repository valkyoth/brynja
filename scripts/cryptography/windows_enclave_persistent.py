#!/usr/bin/env python3
"""Public-marker retained allocation experiment. No production or strict claims."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import windows_enclave_window_guard as guard
from windows_enclave_worker import WorkerNative, LIMIT
from windows_enclave_window_lock import Handshake, validate, flags_check
from windows_protection_api import Windows
from windows_protection_probe import Layout, require

PAGE = 4096
SOURCES = guard.SOURCES + (
    'assurance/windows-enclave-probe/window_rust_x64.asm',
    'assurance/windows-enclave-probe/window_persistent.c',
    'scripts/cryptography/windows_enclave_persistent.py',
    'scripts/cryptography/test-windows-enclave-persistent-native.py')
OPERATIONS = (0, 1, 2, 4, 2, 3, 2, 0, 1, 3)
EXPECTED = ((1, 1), (2, 2), (3, 2), (5, 2), (3, 2),
            (4, 0), (10, 0), (1, 1), (2, 2), (4, 0))


class Retained:
    def __init__(self, host, base, deny):
        self.host, self.base, self.deny = host, base, deny
        self.address, self.locked, self.error = None, False, None
        self.events = []
        self.window = None

    def snapshot(self):
        values = self.host.working_set(self.address, Layout(PAGE, PAGE, PAGE))
        flags_check(values, PAGE, True)
        return values

    def __call__(self, argument):
        event = argument & 15
        if event in (0, 1):
            return self.window(argument)
        try:
            address = argument & ~15
            require(event in (8, 9, 10) and self.window.phase == 'admitted', 'live worker storage event')
            require(address % PAGE == 0 and self.base + PAGE <= address
                    and address + 2 * PAGE <= self.base + LIMIT, 'slot allocation inside enclave')
            require(address + 2 * PAGE <= self.window.low - PAGE or
                    address - PAGE >= self.window.low + 65536 + PAGE, 'slot disjoint from guarded worker')
            if event == 8:
                require(not self.locked, 'no overlapping slot lock')
                self.address = address
                if self.deny:
                    self.events.append({'event': 'deny', 'offset': address - self.base})
                    return 0
                before = self.host.working_set(address, Layout(PAGE, PAGE, PAGE))
                flags_check(before, PAGE, False)
                self.host.lock(address, PAGE)
                self.locked = True
                self.events.append({'event': 'lock', 'offset': address - self.base,
                                    'before': before, 'locked': self.snapshot()})
            else:
                require(self.locked and address == self.address, 'exact retained slot ownership')
                self.events.append({'event': 'check' if event == 9 else 'clear',
                                    'offset': address - self.base, 'locked': self.snapshot()})
                if event == 10:
                    self.host.unlock(address, PAGE)
                    self.locked = False
                    self.events.append({'event': 'unlock', 'offset': address - self.base})
            return 1
        except BaseException as error:
            self.error = error
            return 0


def validate_slot(report, base, low, high, index, deny):
    require(type(report) is list and len(report) == 11 and
            all(type(v) is int and 0 <= v < 1 << 64 for v in report), 'complete storage report')
    status, region, data, state, filled, checked, cleared, freed, error, faults, restricted = report
    operation = 0 if deny else OPERATIONS[index]
    expected_status, expected_state = (11, 0) if deny else EXPECTED[index]
    require((status, state) == (expected_status, expected_state), f'slot outcome: {report}')
    absent = not deny and index == 6
    if absent:
        require(region == data == 0, 'freed slot has no live pointer')
    else:
        require(region % PAGE == 0 and base <= region < data == region + PAGE and
                region + 3 * PAGE <= base + LIMIT, 'exact independent three-page region')
        require(region + 3 * PAGE <= low - PAGE or region >= high + PAGE,
                'retained allocation cannot overlap cleared worker')
    require(filled == (PAGE if operation == 1 else 0) and
            checked == (PAGE if operation == 2 and not absent else 0) and
            cleared == (PAGE if operation == 3 else 0) and
            freed == int(deny or operation == 3) and error == 0 and
            faults == (4 if operation == 4 else 0) and restricted == 1,
            'exact fill/retention/clear/free/guard observations')
    return [status, region - base if region else 0, data - base if data else 0,
            state, filled, checked, cleared, freed, error, faults, restricted]


def validate_events(events, deny):
    names = ['deny'] if deny else [
        'lock', 'check', 'check', 'check', 'check', 'check', 'clear', 'unlock',
        'lock', 'check', 'check', 'clear', 'unlock']
    require(type(events) is list and [e.get('event') for e in events] == names, 'exact slot event order')
    address = None
    for event in events:
        name = event['event']
        keys = {'event', 'offset'} | ({'before', 'locked'} if name == 'lock' else
                                    {'locked'} if name in ('check', 'clear') else set())
        require(set(event) == keys and type(event['offset']) is int and
                PAGE <= event['offset'] <= LIMIT - 2 * PAGE and event['offset'] % PAGE == 0,
                'bounded canonical slot event')
        if name in ('lock', 'deny'):
            address = event['offset']
        require(event['offset'] == address, 'stable slot through release')
        if name == 'lock':
            flags_check(event['before'], PAGE, False)
        if 'locked' in event:
            flags_check(event['locked'], PAGE, True)


def exercise(api, host, image, deny):
    require(api.machine == '0x8664' and host.geometry() == (PAGE, 65536), 'native geometry')
    base = api.create()
    initialized, calls, trampoline = False, [], None
    storage = Retained(host, base, deny)
    try:
        loaded, error = api.load(base, image)
        require(loaded, f'image load: {error}')
        count = api.initialize_worker(base)
        initialized = True
        require(count == 1, 'one synchronous worker')
        def export(name):
            return api.check(api.GetProcAddress(base, name.encode()), name)
        routine, window = export('PublicPersistent'), export('PublicLockedWindow')
        register, control = export('PublicLockedHost'), export('PublicPersistentControl')
        guards = export('PublicGuardControl')
        require(api.call(routine, 0) == api.call(control, 999) == 0, 'unregistered/unknown rejection')
        for index, operation in enumerate((0,) if deny else OPERATIONS):
            storage.window = Handshake(host, base)
            trampoline = guard.callback(storage)
            require(api.call(register, c.cast(trampoline, c.c_void_p).value) == 1, 'register')
            values = [api.call(routine, operation)] + [api.call(window, op) for op in range(2, 9)]
            report = [api.call(control, op) for op in range(16, 27)]
            if storage.error or storage.window.error:
                raise RuntimeError(f'storage callback failed: report={report}') from (storage.error or storage.window.error)
            item = validate(values, base, False, False, False, storage.window.trace,
                            storage.window.snapshots, storage.window.locked)
            item['guards'] = guard.validate_guards([api.call(guards, op) for op in range(16, 29)],
                                                   base, values[1], values[2], 'normal', False)
            item['slot'] = validate_slot(report, base, values[1], values[2], index, deny)
            item['retained_flags'] = storage.snapshot() if storage.locked else []
            calls.append(item)
            require(api.call(register, 0) == 1 and api.call(routine, 0) == 0, 'unregister')
        require(not storage.locked, 'no retained lock after successful campaign')
        validate_events(storage.events, deny)
    finally:
        try:
            if initialized:
                api.terminate(base)
        finally:
            api.delete(base)
    return {**dict.fromkeys(guard.NONCLAIMS, False), 'synthetic_only': True, 'deleted': True,
            'native_machine': '0x8664', 'denied': deny, 'calls': calls, 'events': storage.events}


def validate_record(value, deny):
    require(type(value) is dict and all(value.get(k) is False for k in guard.NONCLAIMS)
            and value.get('synthetic_only') is True and value.get('deleted') is True and
            value.get('native_machine') == '0x8664' and value.get('denied') is deny, 'nonqualifying record')
    calls = value.get('calls')
    require(type(calls) is list and len(calls) == (1 if deny else len(OPERATIONS)), 'complete campaign')
    events = value.get('events')
    validate_events(events, deny)
    cursor, previous = 0, None
    for index, call in enumerate(calls):
        values = call.get('values', [])
        checked = validate(values, 0, False, False, False, call.get('trace'),
                           call.get('snapshots'), call.get('locked_until_teardown'))
        checked['guards'] = guard.validate_guards(call.get('guards', []), 0, values[1], values[2], 'normal', False)
        checked['slot'] = validate_slot(call.get('slot'), 0, values[1], values[2], index, deny)
        operation = 0 if deny else OPERATIONS[index]
        region, data = checked['slot'][1:3]
        if operation == 0:
            previous = region
        elif region:
            require(region == previous, 'same allocation across worker returns')
        count = 1 if deny else 0 if index == 6 else 3 if operation == 3 else 1
        require(all(event['offset'] == data for event in events[cursor:cursor + count]),
                'events bound to reported allocation')
        cursor += count
        flags = call.get('retained_flags')
        live = not deny and EXPECTED[index][1] != 0
        if live:
            flags_check(flags, PAGE, True)
        else:
            require(flags == [], 'released slot not claimed locked')
        checked['retained_flags'] = flags
        require(checked == call, 'canonical complete call')
    require(cursor == len(events), 'all storage events consumed')
    require(set(value) == set(guard.NONCLAIMS) | {'synthetic_only', 'deleted', 'native_machine',
                                               'denied', 'calls', 'events'}, 'canonical envelope')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--deny', action='store_true')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    require(image.suffix.lower() == '.dll' and 0 < image.stat().st_size <= 4 * 1024 * 1024, 'bounded image')
    if args.child:
        print(json.dumps(exercise(WorkerNative(), Windows(), image, args.deny)))
        return
    root = Path(__file__).resolve().parents[2]
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'clean checkout')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    hashes = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in SOURCES}
    image_hash = hashlib.sha256(image.read_bytes()).hexdigest()
    command = [sys.executable, __file__, str(image), '--child'] + (['--deny'] if args.deny else [])
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 262144,
            f'bounded native storage child failed ({result.returncode}): ' + result.stderr[-6000:])
    record = validate_record(json.loads(result.stdout), args.deny)
    require(image_hash == hashlib.sha256(image.read_bytes()).hexdigest() and
            hashes == {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in SOURCES}, 'unchanged inputs')
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root) and
            commit == subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(), 'unchanged checkout')
    record.update(schema=1, kind='windows-enclave-persistent-allocation-experiment', status='OBSERVATIONS_ONLY',
                  commit=commit, source_sha256=hashes, image_sha256=image_hash, os=sys.getwindowsversion().build)
    print(json.dumps(record, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
