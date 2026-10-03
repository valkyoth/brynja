"""Exercise real host orchestration with synthetic calls; NOT VBS evidence."""
import copy
import importlib.util
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

from windows_enclave_parallel_scheduler_host import Dispatch
from windows_enclave_parallel_scheduler_native import cases
from windows_enclave_parallel_scheduler_validate import validate
from windows_enclave_concurrent import INVALID
from windows_protection_probe import ProbeError

spec = importlib.util.spec_from_file_location('wave_support', Path(__file__).with_name('test-windows-enclave-parallel-wave-native.py'))
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)
BASE = 0x10000000


@patch('windows_enclave_parallel_scheduler_host.host_read_rejected', return_value=299)
def fixture(case, _read_probe):
    host = support.Host()
    leaves = (case['input_bits'] + case['block']*8-1)//(case['block']*8)
    class Api:
        def __init__(self):
            self.current, self.lanes, self.open, self.retired = 0, 0, False, True
            self.claims, self.values = set(), {}
            self.lock = threading.Lock()
        def frame(self, lane):
            low = BASE + (lane+1)*0x20000
            gen = 0 if lane == 4 else self.current
            admitted = dispatch(low | lane << 4)
            assert dispatch(low | lane << 4 | 1) == 1
            self.values[gen, lane] = [low, low+65536, low+1024 if admitted else 0, admitted, 1, 1, admitted, 0]
            return 1 if admitted else INVALID
        def call(self, entry, word):
            if entry == 'state':
                return self.current << 32 | ((1 << self.lanes)-1) << 12 | 1 << 16
            if entry == 'query':
                gen, lane, field = word // 256, word // 16 % 16, word % 16
                if (gen, lane) == (0, 4): return self.values.get((gen, lane), [INVALID]*8)[field]
                if gen != self.current or gen == 0 or lane >= 4 or self.open or self.retired: return INVALID
                return self.values.get((gen, lane), [INVALID]*8)[field]
            gen, lane = divmod(word, 16)
            with self.lock:
                if not self.open or gen != self.current or lane >= self.lanes or word in self.claims: return INVALID
                self.claims.add(word)
            return self.frame(lane)
    api = Api()
    dispatch = Dispatch(api, host, BASE, 'leaf', 'query', 'state', case)
    low = BASE + 5*0x20000
    admitted = dispatch(low | 4 << 4)
    if admitted:
        for gen in range(1, (leaves+3)//4 + 1):
            api.current, api.lanes, api.open, api.retired = gen, min(4, leaves-(gen-1)*4), True, False
            assert dispatch(low | 4 << 4 | 2) == 1, dispatch.errors
            api.open = False
            assert dispatch(low | 4 << 4 | 3) == 1, dispatch.errors
            assert dispatch(low | 4 << 4 | 4) == 1, dispatch.errors
            if case['mode'] in ('empty', 'partial', 'deny') and gen == case['fail_at']: break
            api.retired = True
    assert dispatch(low | 4 << 4 | 1) == 1
    api.values[0, 4] = [low, low+65536, low+1024 if admitted else 0, admitted, 1, 1, admitted, 0]
    dispatch.collect(0, 4)
    success = case['mode'] in ('normal', 'early')
    completed = dispatch.completed
    for gen in range(1, completed+2):
        for lane in range(4):
            dispatch.reject(gen, lane)
            if success: dispatch.reject(gen, lane, query=True)
    assert not dispatch.errors and not dispatch.active and not host.locked
    return dict(case=case, result=1 if success else INVALID if not admitted else 0,
        threads=5, completed=completed, frames=list(dispatch.frames.values()), events=dispatch.events,
        rejections=dispatch.rejections, leaf_results=dispatch.results,
        copy_counts=[1, int(case['custom_bits'] != 0), completed, 2 if success else 0, 0] if admitted else [0]*5,
        final_state=completed << 32 if success or not admitted else completed << 32 | 1 << 17,
        output_matches=success, output_unchanged=not success or case['output_bits'] == 0,
        working_set_budget=dict(before=[204800, 1413120], requested=[8388608, 16777216],
                               after=[8388608, 16777216], child_process_only=True),
        enclave_execution=True, public_fixture_only=True, joined=True, production_qualified=False,
        whole_image_cleanup_qualified=False)


class Tests(unittest.TestCase):
    def test_all_variable_shapes_and_dispatch_failures(self):
        self.assertEqual(len(cases()), 31)
        for case in cases():
            with self.subTest(case=case): validate(fixture(case))

    def test_every_stage_requires_observations(self):
        original = fixture(cases()[4])
        for field in ('frames', 'events', 'rejections'):
            altered = copy.deepcopy(original)
            altered[field].pop()
            with self.assertRaises(ProbeError): validate(altered)
        for field in ('joined', 'production_qualified', 'whole_image_cleanup_qualified', 'output_matches', 'output_unchanged'):
            altered = copy.deepcopy(original)
            altered[field] = not altered[field]
            with self.assertRaises(ProbeError): validate(altered)
        for value in (0, 1, (5 << 32) | 1 << 16, (5 << 32) | 1 << 20):
            altered = copy.deepcopy(original)
            altered['final_state'] = value
            with self.assertRaises(ProbeError): validate(altered)
        for i in range(5):
            altered = copy.deepcopy(original)
            altered['copy_counts'][i] += 1
            with self.assertRaises(ProbeError): validate(altered)

    def test_each_reused_frame_requires_cleanup_residency_and_reads(self):
        original = fixture(cases()[4])
        for index in range(len(original['frames'])):
            for field in ('trace', 'snapshots', 'host_read_errors'):
                altered = copy.deepcopy(original)
                altered['frames'][index][field] = {} if field == 'snapshots' else []
                with self.assertRaises(ProbeError): validate(altered)
            altered = copy.deepcopy(original)
            altered['frames'][index]['values'][4] = 0
            with self.assertRaises(ProbeError): validate(altered)


if __name__ == '__main__': unittest.main()
