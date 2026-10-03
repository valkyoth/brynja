"""Public-marker concurrent guarded-stack experiment; not secret-owner qualification."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

from windows_enclave_concurrent import ConcurrentNative, INVALID, ROOT, SOURCES as BASE_SOURCES
from windows_enclave_window_lock import Handshake, geometry
from windows_protection_api import Windows
from windows_protection_probe import require

MODES = ('normal', 'deny', 'after-lock', 'missing-clear')
SOURCES = tuple(sorted(set(BASE_SOURCES + (
    'assurance/windows-enclave-probe/concurrent_stack.c',
    'assurance/windows-enclave-probe/concurrent_stack_x64.asm',
    'scripts/cryptography/windows_enclave_concurrent_stack.py',
    'scripts/cryptography/windows_enclave_concurrent_stack_build.py',
    'scripts/cryptography/test-windows-enclave-concurrent-stack.py',
    'scripts/cryptography/windows_enclave_window_lock.py',
    'scripts/cryptography/windows_enclave_worker.py'))))


def working_set_budget(host):
    """Explicit child-process resource setup, not a lock-success override."""
    host.bind('GetProcessWorkingSetSize', c.c_int32,
              [c.c_void_p, c.POINTER(c.c_size_t), c.POINTER(c.c_size_t)])
    host.bind('SetProcessWorkingSetSize', c.c_int32,
              [c.c_void_p, c.c_size_t, c.c_size_t])
    process = host.dll.GetCurrentProcess()

    def read():
        low, high = c.c_size_t(), c.c_size_t()
        host.ok(host.dll.GetProcessWorkingSetSize(process, c.byref(low), c.byref(high)),
                'read child working-set allowance')
        require(0 < low.value <= high.value, 'valid working-set bounds')
        return [low.value, high.value]

    before = read()
    requested = [max(before[0], 8 * 1024 * 1024), max(before[1], 16 * 1024 * 1024)]
    host.ok(host.dll.SetProcessWorkingSetSize(process, *requested), 'set child working-set allowance')
    after = read()
    require(after[0] >= requested[0] and after[1] >= requested[1], 'working-set allowance confirmed')
    return dict(before=before, requested=requested, after=after, child_process_only=True)


def host_read_rejected(host, address):
    """Attempt one public-marker byte; record failure, never returned memory."""
    host.bind('ReadProcessMemory', c.c_int32,
              [c.c_void_p, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)])
    output, copied = (c.c_ubyte * 1)(0x5a), c.c_size_t()
    c.set_last_error(0)
    ok = host.dll.ReadProcessMemory(host.dll.GetCurrentProcess(), address, output, 1, c.byref(copied))
    error = c.get_last_error()
    require(not ok and copied.value == 0 and output[0] == 0x5a and error != 0,
            'host read must fail without copying a byte')
    return error


class WindowsHandshake:
    def __init__(self, host, base, mode):
        self.base = base
        self.lock = threading.Lock()
        self.ranges = {}
        self.error = None
        self.lanes = [Handshake(host, base, deny=mode == 'deny' and lane == 2,
                                fault='after-lock' if mode == 'after-lock' and lane == 2 else None)
                      for lane in range(4)]

    def __call__(self, argument):
        try:
            require(type(argument) is int and 0 < argument < 1 << 64, 'callback word')
            tag, low = argument & 4095, argument & ~4095
            lane, event = tag >> 4, tag & 15
            require(lane < 4 and event in (0, 1), 'callback slot/event')
            geometry(low, self.base)
            with self.lock:
                if event == 0:
                    require(lane not in self.ranges, 'unique slot admission')
                    # Guards as well as windows must be disjoint.
                    area = (low - 4096, low + 65536 + 4096)
                    require(all(area[1] <= other[0] or other[1] <= area[0]
                                for other in self.ranges.values()), 'disjoint worker windows')
                    self.ranges[lane] = area
                else:
                    require(lane in self.ranges and low == self.ranges[lane][0] + 4096,
                            'finish belongs to same worker window')
                return self.lanes[lane](low | event)
        except BaseException as error:
            self.error = str(error)
            return 0


def validate(record, mode):
    require(mode in MODES and record['mode'] == mode, 'known matching stack mode')
    for name in ('threads', 'active_mask', 'completed_mask', 'exhausted_mask'):
        require(type(record[name]) is int, 'integer control metadata')
    budget = record['working_set_budget']
    require(budget['child_process_only'] is True, 'child-only resource setup')
    for name in ('before', 'requested', 'after'):
        bounds = budget[name]
        require(type(bounds) is list and len(bounds) == 2
                and all(type(value) is int for value in bounds)
                and 0 < bounds[0] <= bounds[1] < 1 << 64, 'working-set bounds')
    require(budget['requested'] == [max(budget['before'][0], 8 * 1024 * 1024),
                                    max(budget['before'][1], 16 * 1024 * 1024)]
            and all(after >= requested for after, requested in zip(budget['after'], budget['requested'])),
            'confirmed requested working-set allowance')
    denied = mode in ('deny', 'after-lock')
    mutant = mode == 'missing-clear'
    mask = 11 if denied else 15
    expected = [INVALID if mutant or (denied and lane == 2) else lane + 100 for lane in range(4)]
    require(record['results'] == expected and record['active_mask'] == mask
            and record['completed_mask'] == mask and record['exhausted_mask'] == 0,
            'complete concurrent execution/accounting')
    require(record['threads'] == 5 and record['joined'] is True and record['deleted'] is True
            and record['synthetic_only'] is True and record['production_qualified'] is False,
            'bounded diagnostic lifecycle')
    require(len(record['lanes']) == 4, 'four worker observations')
    ranges = []
    for lane, item in enumerate(record['lanes']):
        require(type(item['values']) is list and len(item['values']) == 8
                and all(type(value) is int and 0 <= value < 1 << 64 for value in item['values']),
                'complete integer slot observations')
        low, high, marker, admitted, cleared, restored, body, changed = item['values']
        geometry(low, 0)
        require(high == low + 65536 and low % 4096 == 0, 'exact per-worker window')
        area = low - 4096, high + 4096
        require(all(area[1] <= other[0] or other[1] <= area[0] for other in ranges),
                'disjoint stack/guard ranges')
        ranges.append(area)
        ran = not (denied and lane == 2)
        errors = item['host_read_errors']
        require(type(errors) is list and len(errors) == (3 if ran else 0)
                and all(type(error) is int and 0 < error < 1 << 32 for error in errors),
                'three rejected live host reads per admitted worker')
        require(admitted == int(ran) and body == int(ran) and cleared == int(not mutant)
                and restored == 1 and changed == 0, 'per-slot admission/cleanup/restoration')
        require((low <= marker <= high - 256) if ran else marker == 0, 'marker stays in its window')
        require(item['locked_until_teardown'] is mutant, 'exact remaining lock ownership')
        trace = ['admit', 'deny'] if mode == 'deny' and lane == 2 else ['admit', 'lock']
        after_lock = mode == 'after-lock' and lane == 2
        if after_lock:
            trace += ['callback-error']
        elif ran:
            trace += ['all-pages-locked', 'admit-ack']
        if not mutant:
            trace += ['clear-confirmed']
            if not (mode == 'deny' and lane == 2):
                trace += ['still-locked', 'unlock']
            trace += ['finish-ack']
        require(item['trace'] == trace, 'per-slot lock and cleanup ordering')
        require(item['callback_error'] == ('injected callback fault: after-lock' if after_lock else None),
                'only the deliberate callback failure is accepted')
        from windows_enclave_window_lock import flags_check
        names = set() if mode == 'deny' and lane == 2 else {'before'}
        if ran:
            names.add('admitted')
        if not mutant and not (mode == 'deny' and lane == 2):
            names.add('cleared')
        require(set(item['snapshots']) == names, 'complete per-slot page observations')
        for name, flags in item['snapshots'].items():
            flags_check(flags, 65536, name != 'before')


def exercise(api, host, image, mode, budget):
    require(mode in MODES and api.machine == '0x8664' and host.geometry() == (4096, 65536),
            'native x64 geometry and explicit mode')
    base = api.create()
    initialized, control, trampoline = False, None, None
    workers, results, failures = [], [None] * 4, [None] * 4
    handshake = WindowsHandshake(host, base, mode)

    def worker(lane):
        try:
            results[lane] = api.call(entry, lane)
        except Exception as error:
            failures[lane] = str(error)

    try:
        loaded, error = api.load(base, image)
        require(loaded, f'stack image load: {error}')
        threads = api.initialize(base)
        initialized = True
        require(threads == 5, 'five enclave threads required')
        entry = api.export(base, b'PublicStackWorker')
        query = api.export(base, b'PublicStackQuery')
        register = api.export(base, b'PublicStackRegister')
        control = api.export(base, b'PublicConcurrentControl')
        require(api.call(entry, 0) == INVALID and api.call(register, 0) == 0,
                'unregistered worker/null callback reject')
        trampoline = c.WINFUNCTYPE(c.c_void_p, c.c_void_p)(handshake)
        pointer = c.cast(trampoline, c.c_void_p).value
        require(api.call(register, pointer) == 1 and api.call(register, pointer) == 0,
                'immutable callback registration')
        require(api.call(entry, 4) == INVALID and api.call(query, 0) == INVALID,
                'invalid lane/unpublished observation reject')
        for lane in range(4):
            thread = threading.Thread(target=worker, args=(lane,), daemon=True)
            thread.start()
            workers.append(thread)
        mask = 11 if mode in ('deny', 'after-lock') else 15
        deadline = time.monotonic() + 10
        while (observed := api.call(control, 0)) != mask:
            if time.monotonic() >= deadline or any(failures) or handshake.error:
                diagnostic = dict(active=observed, results=results, failures=failures,
                                  callback=handshake.error,
                                  lanes=[{'trace': item.trace, 'error': str(item.error)}
                                         for item in handshake.lanes],
                                  slots=[[api.call(query, lane * 16 + field) for field in range(8)]
                                         for lane in range(4)])
                require(False, 'admitted workers failed to overlap: ' + repr(diagnostic))
            time.sleep(0.01)
        require(api.call(query, 0) == INVALID and api.call(entry, 0) == INVALID,
                'active query and duplicate worker reject')
        read_errors = []
        for lane in range(4):
            if mask & (1 << lane):
                low = handshake.ranges[lane][0] + 4096
                read_errors.append([host_read_rejected(host, low + offset)
                                    for offset in (128, 32768, 65408)])
            else:
                read_errors.append([])
        require(api.call(control, 1) == 1, 'release workers')
        for thread in workers:
            thread.join(max(0, deadline - time.monotonic()))
        require(not any(t.is_alive() for t in workers) and not any(failures)
                and handshake.error is None, 'joined nonfaulting workers')
        observations = []
        for lane in range(4):
            values = [api.call(query, lane * 16 + field) for field in range(8)]
            for field in (0, 1, 2):
                if values[field]:
                    values[field] -= base
            item = handshake.lanes[lane]
            observations.append(dict(values=values, trace=item.trace, snapshots=item.snapshots,
                                     callback_error=str(item.error) if item.error else None,
                                     locked_until_teardown=item.locked, host_read_errors=read_errors[lane]))
        completed, exhausted = api.call(control, 2), api.call(control, 3)
        require(api.call(control, 0) == 0 and api.call(entry, 0) == INVALID, 'idle replay rejection')
    finally:
        try:
            if control is not None:
                api.call(control, 1)
        finally:
            deadline = time.monotonic() + 10
            for thread in workers:
                thread.join(max(0, deadline - time.monotonic()))
            require(not any(t.is_alive() for t in workers), 'refuse deletion with live workers')
            try:
                if initialized:
                    api.terminate(base)
            finally:
                api.delete(base)
    record = dict(mode=mode, threads=threads, active_mask=mask, completed_mask=completed,
                  exhausted_mask=exhausted, results=results, lanes=observations, joined=True,
                  deleted=True, synthetic_only=True, production_qualified=False, working_set_budget=budget)
    validate(record, mode)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('mode', choices=MODES)
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    require(image.suffix.lower() == '.dll' and 0 < image.stat().st_size < 4 * 1024 * 1024,
            'bounded diagnostic image')
    if args.child:
        host = Windows()
        budget = working_set_budget(host)
        record = exercise(ConcurrentNative(), host, image, args.mode, budget)
        print(json.dumps(record))
        return
    before = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    result = subprocess.run([sys.executable, __file__, str(image), args.mode, '--child'],
                            capture_output=True, text=True, timeout=45)
    require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) < 32768,
            'clean bounded stack child: ' + result.stderr[-4096:])
    record = json.loads(result.stdout)
    validate(record, args.mode)
    require(before == {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}
            and digest == hashlib.sha256(image.read_bytes()).hexdigest(), 'stack inputs changed')
    record.update(schema=1, status='OBSERVATIONS_ONLY', source_sha256=before,
                  image_sha256=digest, windows_build=sys.getwindowsversion().build)
    print(json.dumps(record, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
