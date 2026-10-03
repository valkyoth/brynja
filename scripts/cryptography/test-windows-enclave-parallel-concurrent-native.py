"""Model/evidence tests only; real VBS observations are a separate campaign."""
import copy
import unittest
from unittest.mock import patch

from windows_enclave_parallel_concurrent_native import Dispatch, MODES, validate, INVALID
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
    def working_set(self, start, layout):
        return [1 | ((1 << 22) if start in self.locked else 0)] * 16


def fixture(mode):
    host = Host()
    lows = [BASE + 0x10000 + lane * 0x20000 for lane in range(5)]
    class Api:
        def call(self, entry, lane):
            admitted = dispatch(lows[lane] | lane << 4)
            assert dispatch(lows[lane] | lane << 4 | 1) == 1
            return 1 if admitted else INVALID
    dispatch = Dispatch(Api(), host, BASE, None, mode)
    with patch('windows_enclave_parallel_concurrent_native.host_read_rejected', return_value=299):
        root_admitted = dispatch(lows[4] | 4 << 4)
        if root_admitted:
            assert dispatch(lows[4] | 4 << 4 | 2) == 1
        assert dispatch(lows[4] | 4 << 4 | 1) == 1
    assert not dispatch.errors and not host.locked
    frames = []
    for lane, item in enumerate(dispatch.lanes):
        if lane not in dispatch.ranges: continue
        low = lows[lane] - BASE
        admitted = int(not item.deny)
        frames.append(dict(lane=lane, values=[low, low + 65536, low + 1024 if admitted else 0,
            admitted, 1, 1, admitted, 0], trace=item.trace, snapshots=item.snapshots,
            host_read_errors=dispatch.read_errors.get(lane, [])))
    return dict(mode=mode, identity=1, result=1 if mode == 'normal' else INVALID if mode == 'root-deny' else 0,
        frames=frames, leaf_results=dispatch.results, events=dispatch.events, threads=5,
        root_stayed_live=True, joined=True, public_fixture_only=True,
        production_qualified=False, whole_image_cleanup_qualified=False,
        working_set_budget=dict(before=[204800, 1413120], requested=[8388608, 16777216],
                                after=[8388608, 16777216], child_process_only=True))


class Tests(unittest.TestCase):
    def test_all_modes_execute_real_orchestrator(self):
        for mode in MODES:
            with self.subTest(mode=mode): validate(fixture(mode))

    def test_complete_record_rejects_qualification_and_missing_work(self):
        normal = fixture('normal')
        for key, value in (('result', 0), ('identity', 9), ('threads', 4), ('joined', False),
                           ('root_stayed_live', False), ('public_fixture_only', False),
                           ('production_qualified', True), ('whole_image_cleanup_qualified', True),
                           ('leaf_results', [1, 1, None, 1]), ('events', normal['events'][:-1]),
                           ('frames', normal['frames'][:-1]), ('frames', normal['frames'] + normal['frames'][:1])):
            record = copy.deepcopy(normal)
            record[key] = value
            with self.subTest(key=key), self.assertRaises(ProbeError): validate(record)

    def test_every_frame_requires_admission_clear_residency_and_failed_reads(self):
        normal = fixture('normal')
        for lane in range(5):
            for field, value in ((1, 0), (2, 1), (3, 0), (4, 0), (5, 0), (6, 0), (7, 1)):
                record = copy.deepcopy(normal)
                record['frames'][lane]['values'][field] = value
                with self.subTest(lane=lane, field=field), self.assertRaises(ProbeError): validate(record)
            for name, value in (('trace', []), ('snapshots', {}), ('host_read_errors', [0, 0, 0])):
                record = copy.deepcopy(normal)
                record['frames'][lane][name] = value
                with self.subTest(lane=lane, name=name), self.assertRaises(ProbeError): validate(record)

    def test_overlapping_windows_and_premature_root_finish_reject(self):
        normal = fixture('normal')
        record = copy.deepcopy(normal)
        record['frames'][1]['values'][:3] = record['frames'][0]['values'][:3]
        with self.assertRaises(ProbeError): validate(record)
        record = copy.deepcopy(normal)
        record['events'].insert(2, record['events'].pop())
        with self.assertRaises(ProbeError): validate(record)

    def test_callback_rejects_wrong_lane_range_event_and_replay(self):
        dispatch = Dispatch(None, Host(), BASE, None, 'empty')
        low = BASE + 0x10000
        self.assertEqual(dispatch(low | 4 << 4), 1)
        for word in (None, 0, low | 5 << 4, low | 4 << 4 | 9, low | 4 << 4,
                     (low + 65536) | 4 << 4 | 1, low | 1 << 4 | 2):
            with self.subTest(word=word): self.assertEqual(dispatch(word), 0)


if __name__ == '__main__': unittest.main()
