"""Private three-wave PUBLIC-fixture VBS experiment; not production qualification."""
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
from windows_enclave_window_lock import Handshake, geometry
from windows_protection_api import Windows
from windows_protection_probe import require
from windows_enclave_parallel_wave_validate import validate, MODES


class Dispatch:
    def __init__(self, api, host, base, entry, query, mode, fail_at):
        self.api, self.host, self.base, self.entry, self.query = api, host, base, entry, query
        self.mode, self.fail_at = mode, fail_at
        self.lock = threading.Lock()
        self.active, self.ranges, self.reads, self.frames, self.results = {}, {}, {}, {}, {}
        self.errors, self.events, self.workers, self.rejections = [], [], [], []
        self.current = self.completed = 0
        self.release, self.admitted = threading.Event(), threading.Event()
        self.handshakes = {12: Handshake(host, base, deny=mode == 'root-deny')}

    def selected(self, mode):
        return self.mode == mode and self.current == self.fail_at

    def reject(self, word):
        result = self.api.call(self.entry, word)
        require(result == INVALID, 'stale/future/inactive/duplicate context rejected before entry')
        with self.lock: self.rejections.append([self.current, word, result])

    def observe(self):
        with self.lock:
            for index, area in self.active.items():
                if not self.handshakes[index].deny:
                    self.reads[index] = [host_read_rejected(self.host, area[0] + 4096 + offset)
                                         for offset in (128, 32768, 65408)]
        self.admitted.set()

    def worker(self, generation, lane):
        try:
            index, word = (generation - 1) * 4 + lane, generation * 16 + lane
            self.results[index] = self.api.call(self.entry, word)
            self.reject(word)
        except BaseException as error:
            with self.lock: self.errors.append(str(error))

    def host_join(self):
        for thread in self.workers: thread.join(15)
        require(not any(t.is_alive() for t in self.workers), 'host workers fully returned')
        require(not self.errors, 'worker failures: ' + repr(self.errors))

    def dispatch(self, generation):
        require(self.handshakes[12].phase == 'admitted' and self.current == self.completed
                and generation == self.current + 1 and set(self.active) == {12}, 'next wave after cleanup/join')
        self.current = generation
        self.events.append([12, 2 + generation])
        lanes = 2 if generation == 3 else 4
        for invalid_generation in (0, generation - 1, generation + 1):
            for lane in range(4): self.reject(invalid_generation * 16 + lane)
        for lane in range(lanes, 5): self.reject(generation * 16 + lane)
        self.reject(INVALID)
        self.release.clear()
        self.admitted.clear()
        if self.selected('empty'): return 1
        # Hold denied admission too: otherwise that call can finish and the OS
        # can reuse its stack before the other lanes enter, defeating this
        # diagnostic's deliberately overlapping per-wave frame population.
        count = lanes - int(self.selected('partial'))
        self.barrier = threading.Barrier(count, action=self.observe, timeout=10)
        for lane in range(lanes):
            if self.selected('partial') and lane == 1: continue
            index = (generation - 1) * 4 + lane
            self.handshakes[index] = Handshake(self.host, self.base, deny=self.selected('deny') and lane == 1)
            thread = threading.Thread(target=self.worker, args=(generation, lane), daemon=True)
            self.workers.append(thread)
            thread.start()
        if self.selected('early'):
            require(self.admitted.wait(10), 'all workers held in live admission callbacks')
            # No join and no release: native close callback must unblock workers.
        else:
            self.host_join()
        return 1

    def collect(self, index):
        handshake = self.handshakes[index]
        values = [self.api.call(self.query, index * 16 + field) for field in range(8)]
        require(values[1] == values[0] + 65536 and values[4:6] == [1, 1] and values[7] == 0,
                'native full-window clear/readback and guard restoration')
        require(handshake.phase == 'finished' and not handshake.locked and handshake.error is None,
                'cleanup/unlock acknowledgement complete')
        for field in (0, 1, 2):
            if values[field]: values[field] -= self.base
        self.frames[index] = dict(index=index, values=values, trace=handshake.trace,
            snapshots=handshake.snapshots, host_read_errors=self.reads.get(index, []))

    def __call__(self, word):
        try:
            require(type(word) is int and 0 < word < 1 << 64, 'callback word')
            low, tag = word & ~4095, word & 4095
            index, event = tag >> 4, tag & 15
            geometry(low, self.base)
            require(index <= 12, 'bounded slot identity')
            if event > 1:
                require(index == 12 and low == self.handshakes[12].low, 'root control origin')
                if event in (3, 4, 5): return self.dispatch(event - 2)
                if event == 6 + self.current:
                    require([12, event] not in self.events, 'one close event')
                    self.events.append([12, event])
                    self.release.set()
                    return 1
                require(event == 10 + self.current and [12, 6 + self.current] in self.events
                        and [12, event] not in self.events, 'native join after close')
                self.host_join()
                for slot in list(self.ranges):
                    if slot != 12 and slot not in self.frames: self.collect(slot)
                require(set(self.active) == {12}, 'no previous live worker windows')
                self.events.append([12, event])
                self.completed = self.current
                return 1
            require(index in self.handshakes, 'expected frame')
            with self.lock:
                self.events.append([index, event])
                if event == 0:
                    require(index not in self.ranges, 'fresh per-generation frame record')
                    area = low - 4096, low + 65536 + 4096
                    require(all(area[1] <= other[0] or other[1] <= area[0] for other in self.active.values()),
                            'disjoint live windows/guards')
                    self.active[index] = self.ranges[index] = area
                else:
                    require(index in self.active and low == self.handshakes[index].low, 'matching live finish')
                result = self.handshakes[index](low | event)
                if event == 1 and result == 1: del self.active[index]
            if index != 12 and event == 0 and (result == 1 or self.handshakes[index].deny):
                self.barrier.wait()
                if self.selected('early'): require(self.release.wait(10), 'native close releases held workers')
            return result
        except BaseException as error:
            with self.lock: self.errors.append(str(error))
            return 0


def exercise(image, identity, mode, fail_at):
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
        require(threads == 5, 'five actual enclave threads')
        root = api.export(base, b'PublicWaveRoot')
        leaf = api.export(base, b'PublicWaveWorker')
        query = api.export(base, b'PublicStackQuery')
        register = api.export(base, b'PublicStackRegister')
        dispatch = Dispatch(api, host, base, leaf, query, mode, fail_at)
        trampoline = c.WINFUNCTYPE(c.c_void_p, c.c_void_p)(dispatch)
        pointer = c.cast(trampoline, c.c_void_p).value
        require(api.call(register, pointer) == 1 and api.call(register, pointer) == 0, 'immutable registration')
        result = api.call(root, identity)
        require(api.call(root, identity) == 0, 'root replay rejects')
        require(not dispatch.errors and not dispatch.active, 'callbacks completed: ' + repr(dispatch.errors))
        dispatch.host_join()
        dispatch.collect(12)
        for index in range(13):
            if index not in dispatch.frames:
                require(api.call(query, index * 16) == INVALID, 'unentered frame remains absent')
        for generation in range(1, 4):
            for lane in range(4): dispatch.reject(generation * 16 + lane)
        record = dict(identity=identity, mode=mode, fail_at=fail_at, result=result, threads=threads,
            completed=dispatch.completed, leaf_results=dispatch.results, frames=list(dispatch.frames.values()),
            events=dispatch.events, rejections=dispatch.rejections, working_set_budget=budget,
            root_stayed_live=True, joined=True, public_fixture_only=True,
            production_qualified=False, whole_image_cleanup_qualified=False)
        validate(record)
    finally:
        if dispatch is not None: dispatch.host_join()
        if initialized: api.terminate(base)
        api.delete(base)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--child', action='store_true')
    parser.add_argument('--identity', type=int, default=1)
    parser.add_argument('--mode', choices=MODES, default='normal')
    parser.add_argument('--fail-at', type=int, choices=(1, 2, 3), default=1)
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    if args.child:
        print(json.dumps(exercise(image, args.identity, args.mode, args.fail_at)))
        return
    require(not args.output.exists(), 'fresh output required')
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    cases = [(identity, 'normal', 1) for identity in range(1, 5)]
    cases += [(1, mode, wave) for mode in ('deny', 'empty', 'partial', 'early') for wave in (1, 2, 3)]
    cases += [(1, 'root-deny', 1)]
    records = []
    for identity, mode, wave in cases:
        result = subprocess.run([sys.executable, __file__, str(image), str(args.output), '--child',
            '--identity', str(identity), '--mode', mode, '--fail-at', str(wave)],
            capture_output=True, text=True, timeout=90)
        require(result.returncode == 0 and not result.stderr and len(result.stdout) < 150000,
                f'bounded native child {identity}/{mode}/{wave}: {result.stdout[-1500:]} {result.stderr[-4500:]}')
        record = json.loads(result.stdout)
        validate(record)
        records.append(record)
        print(f'PRIVATE_WAVE_VBS: identity={identity}; mode={mode}; wave={wave}; PASS', flush=True)
    require(digest == hashlib.sha256(image.read_bytes()).hexdigest(), 'unchanged image')
    args.output.write_text(json.dumps(dict(schema=1, image_sha256=digest, records=records,
        windows_build=sys.getwindowsversion().build, status='PRIVATE_PUBLIC_FIXTURE_OBSERVATIONS_ONLY'), indent=2) + '\n')


if __name__ == '__main__': main()
