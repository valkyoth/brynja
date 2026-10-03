"""Copied-input evidence/oracle regressions; synthetic observations, not VBS."""
import copy
import importlib.util
from pathlib import Path
import unittest

from windows_enclave_parallel_input_native import cases, validate, Fixture, COPY_ERRORS, INVALID
from windows_protection_probe import ProbeError

spec = importlib.util.spec_from_file_location('wave_fixture', Path(__file__).with_name('test-windows-enclave-parallel-wave-native.py'))
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def fixture(case):
    mode = case['mode']
    record = support.fixture('normal' if mode in COPY_ERRORS else mode, case['fail_at'])
    if mode in COPY_ERRORS:
        completed = 3 if mode == 'output-address' else 2 if mode == 'input-tail' else 0
        indices = {12} | set(range(completed * 4 if completed < 3 else 10))
        record['frames'] = [f for f in record['frames'] if f['index'] in indices]
        for f in record['frames']:
            if not completed: f['host_read_errors'] = []
        record['events'] = [e for e in record['events'] if e[0] in indices and
            (e[0] != 12 or e[1] <= 1 or any(e[1] == offset + gen for gen in range(1, completed + 1) for offset in (2, 6, 10)))]
        record['leaf_results'] = {k: v for k, v in record['leaf_results'].items() if k in indices}
        # Existing fixture ends with precisely twelve post-close probes.
        rejections = [r for r in record['rejections'][:-12] if r[0] <= completed]
        rejections += [[completed, gen * 16 + lane, INVALID] for gen in range(1, 4) for lane in range(4)]
        record.update(completed=completed, result=0, rejections=rejections)
    success, custom = mode in ('normal', 'early'), int(case['custom_bits'] != 0)
    errors = {
        'header-address': [0, 0, 0, 0, 1], 'custom-address': [1, 0, 0, 0, 1],
        'input-address': [1, custom, 0, 0, 1], 'output-address': [1, custom, 3, 1, 1],
        'reserved': [1, 0, 0, 0, 0], 'custom-tail': [1, custom, 0, 0, 0],
        'input-tail': [1, custom, 3, 0, 0], 'shape': [1, custom, 0, 0, 0],
        'root-deny': [0, 0, 0, 0, 0],
    }
    counts = [1, custom, 3, 2, 0] if success else errors.get(mode, [1, custom, case['fail_at'], 0, 0])
    record.update(case=case, identity=case['identity'], mode=mode, fail_at=case['fail_at'],
        enclave_execution=True, os_copy_executed=mode != 'root-deny', copy_counts=counts,
        output_matches=success, output_unchanged=not success or case['output_bits'] == 0)
    return record


class Tests(unittest.TestCase):
    def test_all_cases_and_oracle_shapes(self):
        self.assertEqual(len(cases()), 31)
        for case in cases():
            with self.subTest(case=case):
                validate(fixture(case))
                data = Fixture(case)
                self.assertEqual(len(data.expected), (case['output_bits'] + 7) // 8)

    def test_every_copy_counter_and_scope_is_load_bearing(self):
        for case in cases():
            original = fixture(case)
            for field in range(5):
                changed = copy.deepcopy(original)
                changed['copy_counts'][field] += 1
                with self.assertRaises(ProbeError): validate(changed)
            for key in ('production_qualified', 'whole_image_cleanup_qualified', 'output_matches', 'output_unchanged', 'os_copy_executed'):
                changed = copy.deepcopy(original)
                changed[key] = not changed[key]
                with self.assertRaises(ProbeError): validate(changed)

    def test_copy_rejections_require_cleanup_join_reads_and_exact_population(self):
        case = next(c for c in cases() if c['mode'] == 'input-tail')
        original = fixture(case)
        for field in ('frames', 'events', 'rejections'):
            changed = copy.deepcopy(original)
            changed[field].pop()
            with self.assertRaises(ProbeError): validate(changed)
        for frame in range(len(original['frames'])):
            for field in ('trace', 'snapshots', 'host_read_errors'):
                changed = copy.deepcopy(original)
                changed['frames'][frame][field] = {} if field == 'snapshots' else []
                with self.assertRaises(ProbeError): validate(changed)
            changed = copy.deepcopy(original)
            changed['frames'][frame]['values'][4] = 0
            with self.assertRaises(ProbeError): validate(changed)
        changed = copy.deepcopy(original)
        changed['leaf_results'] = {}
        with self.assertRaises(ProbeError): validate(changed)
        changed = copy.deepcopy(original)
        changed['working_set_budget']['child_process_only'] = False
        with self.assertRaises(ProbeError): validate(changed)


if __name__ == '__main__': unittest.main()
