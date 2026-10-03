"""Native private PUBLIC-fixture concurrent ParallelHash probe; no qualification."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import threading

from windows_enclave_concurrent import ConcurrentNative, INVALID
from windows_enclave_concurrent_stack import working_set_budget, host_read_rejected
from windows_enclave_window_lock import Handshake, geometry, flags_check
from windows_protection_api import Windows
from windows_protection_probe import require

MODES = ('normal', 'deny', 'empty', 'partial', 'root-deny')


class Dispatch:
    def __init__(self, api, host, base, entry, mode):
        self.api, self.host, self.base, self.entry, self.mode = api, host, base, entry, mode
        self.lock = threading.Lock()
        self.ranges, self.read_errors, self.errors, self.workers = {}, {}, [], []
        self.results = [None] * 4
        self.dispatched = False
        self.events = []
        self.lanes = [Handshake(host, base, deny=(mode == 'deny' and lane == 2)
                               or (mode == 'root-deny' and lane == 4)) for lane in range(5)]
        count = 3 if mode in ('deny', 'partial') else 4
        self.barrier = threading.Barrier(count, action=self.observe, timeout=10)

    def observe(self):
        # Every successful leaf entry and the original root entry are live.
        # Public diagnostic offsets only: never copy CVs or secret bytes out.
        with self.lock:
            for lane, area in self.ranges.items():
                if not self.lanes[lane].deny:
                    self.read_errors[lane] = [host_read_rejected(self.host, area[0] + 4096 + offset)
                                             for offset in (128, 32768, 65408)]

    def worker(self, lane):
        try:
            self.results[lane] = self.api.call(self.entry, lane)
        except BaseException as error:
            self.errors.append(str(error))

    def run(self):
        require(not self.dispatched and self.lanes[4].phase == 'admitted', 'one admitted root dispatch')
        self.dispatched = True
        self.events.append([4, 2])
        if self.mode == 'empty':
            return 1  # Deliberately dishonest host success, without any work.
        for lane in range(4):
            if self.mode == 'partial' and lane == 2:
                continue
            thread = threading.Thread(target=self.worker, args=(lane,), daemon=True)
            thread.start()
            self.workers.append(thread)
        for thread in self.workers:
            thread.join(15)
        require(not any(thread.is_alive() for thread in self.workers), 'host joins every worker')
        require(not self.errors, 'worker calls succeeded: ' + repr(self.errors))
        self.events.append([4, 3])
        return 1

    def __call__(self, argument):
        try:
            require(type(argument) is int and 0 < argument < 1 << 64, 'callback word')
            tag, low = argument & 4095, argument & ~4095
            lane, event = tag >> 4, tag & 15
            require(lane < 5 and event in (0, 1, 2), 'known frame/event')
            geometry(low, self.base)
            if event == 2:
                require(lane == 4 and low == self.lanes[4].low, 'dispatch only from root')
                return self.run()
            with self.lock:
                self.events.append([lane, event])
                if event == 0:
                    require(lane not in self.ranges, 'one admission per frame')
                    area = low - 4096, low + 65536 + 4096
                    require(all(area[1] <= other[0] or other[1] <= area[0]
                                for other in self.ranges.values()), 'five disjoint windows and guards')
                    self.ranges[lane] = area
                else:
                    require(lane in self.ranges and low == self.lanes[lane].low, 'matching finish')
                result = self.lanes[lane](low | event)
            if event == 0 and lane < 4 and result == 1:
                self.barrier.wait()
            return result
        except BaseException as error:
            self.errors.append(str(error))
            return 0


def exercise(image, identity, mode):
    api, host = ConcurrentNative(), Windows()
    budget = working_set_budget(host)
    require(api.machine == '0x8664' and host.geometry() == (4096, 65536), 'x64 page geometry')
    base = api.create()
    initialized, dispatch, trampoline = False, None, None
    try:
        loaded, error = api.load(base, image)
        require(loaded, f'image load failed: {error}')
        threads = api.initialize(base)
        initialized = True
        require(threads == 5, 'actual five-thread enclave initialization')
        root = api.export(base, b'PublicParallelRoot')
        leaf = api.export(base, b'PublicStackWorker')
        query = api.export(base, b'PublicStackQuery')
        register = api.export(base, b'PublicStackRegister')
        dispatch = Dispatch(api, host, base, leaf, mode)
        trampoline = c.WINFUNCTYPE(c.c_void_p, c.c_void_p)(dispatch)
        pointer = c.cast(trampoline, c.c_void_p).value
        require(api.call(register, pointer) == 1 and api.call(register, pointer) == 0,
                'immutable registration')
        result = api.call(root, identity)
        require(not dispatch.errors, 'callback failures: ' + repr(dispatch.errors))
        require(result == (1 if mode == 'normal' else INVALID if mode == 'root-deny' else 0),
                'root must reject incomplete work and admission failure')
        require(api.call(root, identity) == 0, 'one-shot root replay rejected')
        observations = []
        for lane, handshake in enumerate(dispatch.lanes):
            if lane not in dispatch.ranges:
                require(api.call(query, lane * 16) == INVALID, 'unentered frame not published')
                continue
            values = [api.call(query, lane * 16 + field) for field in range(8)]
            require(values[1] == values[0] + 65536 and values[4:6] == [1, 1] and values[7] == 0,
                    'full-frame clear and guard restoration')
            require(values[3] == values[6] == int(not handshake.deny), 'admission before Rust body')
            require(handshake.phase == 'finished' and not handshake.locked and handshake.error is None,
                    'finish acknowledged only after cleanup and unlock')
            for field in (0, 1, 2):
                if values[field]: values[field] -= base
            observations.append(dict(lane=lane, values=values, trace=handshake.trace,
                snapshots=handshake.snapshots, host_read_errors=dispatch.read_errors.get(lane, [])))
        record = dict(identity=identity, mode=mode, result=result, threads=threads,
            leaf_results=dispatch.results, frames=observations, working_set_budget=budget,
            events=dispatch.events,
            root_stayed_live=True, joined=True, public_fixture_only=True,
            production_qualified=False, whole_image_cleanup_qualified=False)
        validate(record)
    finally:
        if dispatch is not None:
            for thread in dispatch.workers:
                thread.join(15)
            require(not any(thread.is_alive() for thread in dispatch.workers),
                    'live calls: refuse unsafe deletion; bounded parent terminates failed child')
        if initialized: api.terminate(base)
        api.delete(base)
    return record


def validate(record):
    mode = record['mode']
    require(mode in MODES and record['identity'] in (1, 2, 3, 4), 'known identity/mode')
    expected_lanes = {4} if mode in ('empty', 'root-deny') else {0, 1, 3, 4} if mode == 'partial' else set(range(5))
    require(len(record['frames']) == len(expected_lanes)
            and {frame['lane'] for frame in record['frames']} == expected_lanes, 'complete frame population')
    expected_results = [None] * 4 if mode in ('empty', 'root-deny') else [1] * 4
    if mode == 'partial': expected_results[2] = None
    if mode == 'deny': expected_results[2] = INVALID
    require(record['leaf_results'] == expected_results, 'exact leaf completion')
    require(record['result'] == (1 if mode == 'normal' else INVALID if mode == 'root-deny' else 0),
            'exact root outcome')
    require(record['threads'] == 5 and record['root_stayed_live'] is True and record['joined'] is True
            and record['public_fixture_only'] is True and record['production_qualified'] is False
            and record['whole_image_cleanup_qualified'] is False, 'honest diagnostic scope')
    budget = record['working_set_budget']
    require(budget['child_process_only'] is True, 'child-only locking allowance')
    for name in ('before', 'requested', 'after'):
        bounds = budget[name]
        require(type(bounds) is list and len(bounds) == 2
                and all(type(value) is int for value in bounds)
                and 0 < bounds[0] <= bounds[1] < 1 << 64, 'valid working-set allowance')
    require(budget['requested'] == [max(budget['before'][0], 8 * 1024 * 1024),
                                    max(budget['before'][1], 16 * 1024 * 1024)]
            and all(after >= requested for after, requested in zip(budget['after'], budget['requested'])),
            'confirmed child working-set allowance')
    events = record['events']
    require(events[0] == [4, 0] and events[-1] == [4, 1], 'root outlives all leaf callbacks')
    expected_events = [[lane, event] for lane in expected_lanes for event in (0, 1)]
    if mode != 'root-deny': expected_events.append([4, 2])
    if mode not in ('root-deny', 'empty'): expected_events.append([4, 3])
    require(sorted(events) == sorted(expected_events), 'complete unique lifecycle events')
    for lane in expected_lanes - {4}:
        require(events.index([4, 2]) < events.index([lane, 0]) < events.index([lane, 1])
                < events.index([4, 3]) < events.index([4, 1]), 'join before root clear')
    ranges = []
    for frame in record['frames']:
        denied = mode == 'deny' and frame['lane'] == 2 or mode == 'root-deny'
        expected = ['admit', 'deny', 'clear-confirmed', 'finish-ack'] if denied else [
            'admit', 'lock', 'all-pages-locked', 'admit-ack', 'clear-confirmed', 'still-locked', 'unlock', 'finish-ack']
        require(frame['trace'] == expected, 'exact residency/cleanup trace')
        values = frame['values']
        require(type(values) is list and len(values) == 8
                and all(type(value) is int and 0 <= value < 1 << 64 for value in values), 'integer frame metadata')
        low, high, marker, admitted, cleared, restored, body, changed = values
        geometry(low, 0)
        require(low >= 4096 and low % 4096 == 0 and high == low + 65536
                and admitted == body == int(not denied) and cleared == restored == 1 and changed == 0,
                'admitted, cleared, restored guarded frame')
        require(marker == 0 if denied else low <= marker <= high - 16, 'body stays within admitted window')
        area = low - 4096, high + 4096
        require(all(area[1] <= other[0] or other[1] <= area[0] for other in ranges), 'disjoint windows/guards')
        ranges.append(area)
        require(set(frame['snapshots']) == (set() if denied else {'before', 'admitted', 'cleared'}),
                'all page observations')
        for name, flags in frame['snapshots'].items(): flags_check(flags, 65536, name != 'before')
        reads = frame['host_read_errors']
        require(len(reads) == (0 if denied or mode == 'empty' else 3)
                and all(type(value) is int and value > 0 for value in reads), 'live host reads rejected')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--child', action='store_true')
    parser.add_argument('--identity', type=int, default=1)
    parser.add_argument('--mode', choices=MODES, default='normal')
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    if args.child:
        print(json.dumps(exercise(image, args.identity, args.mode)))
        return
    require(not args.output.exists(), 'fresh evidence output required')
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    cases = [(identity, 'normal') for identity in range(1, 5)] + [(1, mode) for mode in MODES[1:]]
    records = []
    for identity, mode in cases:
        result = subprocess.run([sys.executable, __file__, str(image), str(args.output), '--child',
                                 '--identity', str(identity), '--mode', mode],
                                capture_output=True, text=True, timeout=60)
        require(result.returncode == 0 and not result.stderr and len(result.stdout) < 100000,
                f'bounded native child {identity}/{mode}: {result.stdout[-2000:]} {result.stderr[-4000:]}')
        record = json.loads(result.stdout)
        validate(record)
        records.append(record)
        print(f'PRIVATE_CONCURRENT_PARALLELHASH: identity={identity}; mode={mode}; PASS', flush=True)
    require(digest == hashlib.sha256(image.read_bytes()).hexdigest(), 'unchanged image')
    args.output.write_text(json.dumps(dict(schema=1, image_sha256=digest, records=records,
        windows_build=sys.getwindowsversion().build, status='PRIVATE_PUBLIC_FIXTURE_OBSERVATIONS_ONLY'), indent=2) + '\n')


if __name__ == '__main__': main()
