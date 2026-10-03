"""Private generation-aware host diagnostic; no cryptography or admission authority."""
import threading

from windows_enclave_concurrent import INVALID
from windows_enclave_concurrent_stack import host_read_rejected
from windows_enclave_window_lock import Handshake, geometry
from windows_protection_probe import require


class Dispatch:
    def __init__(self, api, host, base, entry, query, state, case):
        self.api, self.host, self.base = api, host, base
        self.entry, self.query, self.state, self.case = entry, query, state, case
        self.lock = threading.Lock()
        self.generation = self.completed = 0
        self.lanes = 0
        self.active, self.ranges, self.reads, self.frames, self.results = {}, {}, {}, {}, {}
        self.handshakes = {(0, 4): Handshake(host, base, deny=case['mode'] == 'root-deny')}
        self.errors, self.events, self.workers, self.rejections = [], [], [], []
        self.release, self.admitted = threading.Event(), threading.Event()

    def selected(self, mode):
        return self.case['mode'] == mode and self.generation == self.case['fail_at']

    def reject(self, generation, lane, query=False):
        word = generation * (256 if query else 16) + lane * (16 if query else 1)
        result = self.api.call(self.query if query else self.entry, word)
        require(result == INVALID, 'stale/future/duplicate worker or query rejects')
        with self.lock: self.rejections.append([self.generation, int(query), word, result])

    def host_join(self):
        for thread in self.workers: thread.join(15)
        require(not any(t.is_alive() for t in self.workers), 'workers fully returned')
        require(not self.errors, 'worker failures: ' + repr(self.errors))

    def worker(self, generation, lane):
        try:
            result = self.api.call(self.entry, generation * 16 + lane)
            with self.lock: self.results[generation * 16 + lane] = result
            self.reject(generation, lane)
        except BaseException as error:
            with self.lock: self.errors.append(str(error))

    def observe(self):
        with self.lock:
            for key, area in self.active.items():
                if not self.handshakes[key].deny:
                    self.reads[key] = [host_read_rejected(self.host, area[0] + 4096 + offset)
                                       for offset in (128, 32768, 65408)]
        self.admitted.set()

    def dispatch(self):
        state = self.api.call(self.state, 0)
        generation, mask = state >> 32, (state >> 12) & 15
        lanes = mask.bit_count()
        expected_leaves = (self.case['input_bits'] + self.case['block'] * 8 - 1) // (self.case['block'] * 8)
        require(generation == self.generation + 1 and self.completed == self.generation and
                lanes == min(4, expected_leaves - self.completed * 4) and mask == (1 << lanes) - 1 and
                state & 0xfff == 0 and state & (1 << 16), 'exact new native generation and population')
        require(set(self.active) == {(0, 4)}, 'only root live before next dispatch')
        self.generation, self.lanes = generation, lanes
        self.events.append([generation, 4, 2])
        for invalid in (0, generation - 1, generation + 1):
            for lane in range(4):
                self.reject(invalid, lane)
                self.reject(invalid, lane, query=True)
        for lane in range(lanes, 5): self.reject(generation, lane)
        self.release.clear()
        self.admitted.clear()
        if self.selected('empty'): return 1
        count = lanes - int(self.selected('partial'))
        require(count > 0, 'partial diagnostic retains a worker')
        self.barrier = threading.Barrier(count, action=self.observe, timeout=10)
        for lane in range(lanes):
            if self.selected('partial') and lane == lanes - 1: continue
            key = generation, lane
            self.handshakes[key] = Handshake(self.host, self.base, deny=self.selected('deny') and lane == 0)
            thread = threading.Thread(target=self.worker, args=key, daemon=True)
            self.workers.append(thread)
            thread.start()
        if self.selected('early'):
            require(self.admitted.wait(10), 'workers held before premature host return')
        else: self.host_join()
        return 1

    def collect(self, generation, lane):
        key = generation, lane
        values = [self.api.call(self.query, generation * 256 + lane * 16 + field) for field in range(8)]
        handshake = self.handshakes[key]
        require(values[1] == values[0] + 65536 and values[4:6] == [1, 1] and values[7] == 0,
                'complete native window clearing and guard restoration')
        require(handshake.phase == 'finished' and not handshake.locked and handshake.error is None, 'unlock complete')
        for field in (0, 1, 2):
            if values[field]: values[field] -= self.base
        self.frames[key] = dict(generation=generation, lane=lane, values=values, trace=handshake.trace,
            snapshots=handshake.snapshots, host_read_errors=self.reads.get(key, []))

    def __call__(self, word):
        try:
            require(type(word) is int and 0 < word < 1 << 64, 'callback metadata')
            low, tag = word & ~4095, word & 4095
            lane, event = tag >> 4, tag & 15
            geometry(low, self.base)
            require(lane <= 4, 'bounded native slot')
            if event > 1:
                require(lane == 4 and low == self.handshakes[(0, 4)].low, 'live root control')
                if event == 2: return self.dispatch()
                require(event in (3, 4) and [self.generation, 4, event] not in self.events, 'one close/join')
                if event == 3:
                    self.events.append([self.generation, 4, event])
                    self.release.set()
                    return 1
                require([self.generation, 4, 3] in self.events, 'join follows native close')
                self.host_join()
                for current in range(self.lanes):
                    key = self.generation, current
                    if key in self.handshakes: self.collect(*key)
                    else: self.reject(self.generation, current, query=True)
                require(set(self.active) == {(0, 4)}, 'all reused worker windows finished')
                self.events.append([self.generation, 4, event])
                self.completed = self.generation
                return 1
            key = (0, 4) if lane == 4 else (self.generation, lane)
            require(key in self.handshakes, 'expected generation frame')
            with self.lock:
                self.events.append([*key, event])
                if event == 0:
                    require(key not in self.ranges, 'one admission per generation/lane')
                    area = low - 4096, low + 65536 + 4096
                    require(all(area[1] <= a[0] or a[1] <= area[0] for a in self.active.values()), 'disjoint live windows')
                    self.active[key] = self.ranges[key] = area
                else:
                    require(key in self.active and low == self.handshakes[key].low, 'matching live cleanup')
                result = self.handshakes[key](low | event)
                if event == 1 and result == 1: del self.active[key]
            if lane != 4 and event == 0 and (result == 1 or self.handshakes[key].deny):
                self.barrier.wait()
                if self.selected('early'): require(self.release.wait(10), 'close releases live early-return workers')
            return result
        except BaseException as error:
            with self.lock: self.errors.append(str(error))
            return 0
