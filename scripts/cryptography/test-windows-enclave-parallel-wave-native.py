"""Host orchestration/observation regressions with a synthetic API, NOT VBS."""
import copy
import threading
import unittest
from unittest.mock import patch

from windows_enclave_parallel_wave_native import Dispatch, INVALID
from windows_enclave_parallel_wave_validate import validate, MODES
from windows_protection_probe import ProbeError

BASE = 0x10000000


class Host:
    def __init__(self): self.locked = set()
    def lock(self, start, size):
        assert size == 65536 and start not in self.locked
        self.locked.add(start)
    def unlock(self, start, size):
        assert size == 65536 and start in self.locked
        self.locked.remove(start)
    def working_set(self, start, layout): return [1 | ((1 << 22) if start in self.locked else 0)] * 16


def fixture(mode, fail_at=1):
    host = Host()
    class Api:
        def __init__(self):
            self.current, self.open = 0, False
            self.claims, self.values = set(), {}
            self.lock = threading.Lock()
        def frame(self, index):
            # Deliberately reuse the same worker windows in each later wave.
            low = BASE + (5 if index == 12 else index % 4 + 1) * 0x20000
            admitted = dispatch(low | index << 4)
            assert dispatch(low | index << 4 | 1) == 1
            self.values[index] = [low, low + 65536, low + 1024 if admitted else 0,
                                  admitted, 1, 1, admitted, 0]
            return 1 if admitted else INVALID
        def call(self, entry, word):
            if entry == 'query': return self.values[word // 16][word % 16]
            generation, lane = divmod(word, 16)
            with self.lock:
                if not self.open or generation != self.current or lane >= (2 if generation == 3 else 4) or word in self.claims:
                    return INVALID
                self.claims.add(word)
            return self.frame((generation - 1) * 4 + lane)
    api = Api()
    dispatch = Dispatch(api, host, BASE, 'leaf', 'query', mode, fail_at)
    low = BASE + 5 * 0x20000
    with patch('windows_enclave_parallel_wave_native.host_read_rejected', return_value=299):
        admitted = dispatch(low | 12 << 4)
        if admitted:
            for generation in range(1, 4):
                api.current, api.open = generation, True
                assert dispatch(low | 12 << 4 | (2 + generation)) == 1
                api.open = False
                assert dispatch(low | 12 << 4 | (6 + generation)) == 1
                assert dispatch(low | 12 << 4 | (10 + generation)) == 1
                if mode in ('deny', 'empty', 'partial') and generation == fail_at: break
        assert dispatch(low | 12 << 4 | 1) == 1
    api.values[12] = [low, low + 65536, low + 1024 if admitted else 0, admitted, 1, 1, admitted, 0]
    dispatch.collect(12)
    for generation in range(1, 4):
        for lane in range(4): dispatch.reject(generation * 16 + lane)
    assert not dispatch.errors and not host.locked and not dispatch.active
    return dict(identity=1, mode=mode, fail_at=fail_at, threads=5, completed=dispatch.completed,
        result=1 if mode in ('normal', 'early') else INVALID if mode == 'root-deny' else 0,
        frames=list(dispatch.frames.values()), leaf_results=dispatch.results, events=dispatch.events,
        rejections=dispatch.rejections, root_stayed_live=True, joined=True, public_fixture_only=True,
        production_qualified=False, whole_image_cleanup_qualified=False,
        working_set_budget=dict(before=[204800, 1413120], requested=[8388608, 16777216],
                                after=[8388608, 16777216], child_process_only=True))


class Tests(unittest.TestCase):
    def test_real_orchestrator_modes_and_each_wave(self):
        for mode in MODES:
            for wave in (1, 2, 3):
                with self.subTest(mode=mode, wave=wave): validate(fixture(mode, wave))

    def test_exact_population_completion_replay_and_scope(self):
        normal = fixture('normal')
        for key, value in (('completed', 2), ('result', 0), ('threads', 4), ('joined', False),
                           ('root_stayed_live', False), ('production_qualified', True),
                           ('whole_image_cleanup_qualified', True), ('public_fixture_only', False),
                           ('leaf_results', {}), ('rejections', normal['rejections'][:-1]),
                           ('frames', normal['frames'][:-1]), ('events', normal['events'][:-1])):
            changed = copy.deepcopy(normal)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ProbeError): validate(changed)

    def test_each_frame_requires_cleanup_residency_and_reads(self):
        normal = fixture('normal')
        for index in range(len(normal['frames'])):
            for field, value in ((1, 0), (2, 1), (3, 0), (4, 0), (5, 0), (6, 0), (7, 1)):
                changed = copy.deepcopy(normal)
                changed['frames'][index]['values'][field] = value
                with self.subTest(index=index, field=field), self.assertRaises(ProbeError): validate(changed)
            for field, value in (('trace', []), ('snapshots', {}), ('host_read_errors', [0, 0, 0])):
                changed = copy.deepcopy(normal)
                changed['frames'][index][field] = value
                with self.subTest(index=index, field=field), self.assertRaises(ProbeError): validate(changed)

    def test_reuse_allowed_only_after_join_and_no_live_overlap(self):
        normal = fixture('normal')
        # Fixture intentionally reuses addresses across waves and must pass.
        validate(normal)
        changed = copy.deepcopy(normal)
        changed['frames'][1]['values'][:3] = changed['frames'][0]['values'][:3]
        with self.assertRaises(ProbeError): validate(changed)
        changed = copy.deepcopy(normal)
        events = changed['events']
        left, right = events.index([12, 11]), events.index([12, 4])
        events[left], events[right] = events[right], events[left]
        with self.assertRaises(ProbeError): validate(changed)

    def test_early_host_return_must_precede_clear(self):
        changed = fixture('early', 2)
        validate(changed)
        events = changed['events']
        events.remove([12, 8])
        events.insert(events.index([12, 12]), [12, 8])
        with self.assertRaises(ProbeError): validate(changed)

    def test_denied_worker_remains_live_until_other_lanes_enter(self):
        for wave in (1, 2, 3):
            record = fixture('deny', wave)
            validate(record)
            events = record['events']
            entered = [events.index([index, 0]) for index in range((wave - 1) * 4, (wave - 1) * 4 + (2 if wave == 3 else 4))]
            finished = [events.index([index, 1]) for index in range((wave - 1) * 4, (wave - 1) * 4 + (2 if wave == 3 else 4))]
            self.assertLess(max(entered), min(finished))


if __name__ == '__main__': unittest.main()
