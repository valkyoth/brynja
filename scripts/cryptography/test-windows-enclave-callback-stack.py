"""Focused callback-frame measurement regressions; not native VBS evidence."""
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest

from windows_enclave_callback_stack import SOURCE, header, instrument, validate
from windows_enclave_callback_stack_native import decode


def fixture(count=5):
    low = 0x10000
    record = dict(frames=[dict(generation=0, lane=4, values=[low, low + 65536])],
                  events=[[g, 4, e] for g in range(1, count + 1) for e in (2, 3, 4)])
    rows = [[count, count, low + 0x1008, low + 0x1080,
             low + 0x1008, low + 0x1008, 0] for _ in range(3)] if count else [[0] * 7 for _ in range(3)]
    return rows, record


class Tests(unittest.TestCase):
    def test_empty_and_active_callbacks(self):
        for count in (0, 1, 5, 33): validate(*fixture(count))

    def test_every_field_is_load_bearing(self):
        rows, record = fixture()
        for event in range(3):
            for field, value in enumerate((0, 0, 0, 0x30000, 0, 0x30000, 1)):
                mutant = copy.deepcopy(rows)
                mutant[event][field] = value
                with self.subTest(event=event, field=field), self.assertRaises(ValueError):
                    validate(mutant, record)

    def test_independent_counts_and_empty_measurements(self):
        rows, record = fixture()
        record['events'].pop()
        with self.assertRaises(ValueError): validate(rows, record)
        rows, record = fixture(0)
        rows[0][2] = 1
        with self.assertRaises(ValueError): validate(rows, record)

    def test_exact_types_shape_and_alignment(self):
        rows, record = fixture()
        for value in (True, -1, 1 << 64, '5', None):
            mutant = copy.deepcopy(rows)
            mutant[0][0] = value
            with self.assertRaises(ValueError): validate(mutant, record)
        for value in ([], rows[:2], rows + [rows[0]], [rows[0][:-1], *rows[1:]]):
            with self.assertRaises(ValueError): validate(value, record)
        rows[0][4] += 1
        rows[0][5] += 1
        with self.assertRaises(ValueError): validate(rows, record)

    def test_root_identity_and_bounds(self):
        rows, record = fixture()
        for frames in ([], record['frames'] * 2, [dict(generation=1, lane=4, values=[0, 65536])]):
            with self.assertRaises(ValueError): validate(rows, dict(record, frames=frames))
        record['frames'][0]['values'][1] += 1
        with self.assertRaises(ValueError): validate(rows, record)

    def test_instrumentation_is_unique_and_keeps_real_call(self):
        source = (SOURCE / 'concurrent_stack.c').read_text()
        result = instrument(source)
        self.assertEqual(result.count('#include "callback_stack_probe.h"'), 1)
        with self.assertRaises(ValueError): instrument(result)
        with self.assertRaises(ValueError): instrument(source + source)
        for variant in ('baseline', 'missing-before', 'outside-reply'):
            text = header(variant)
            self.assertEqual(text.count('CallEnclave(stack_callback,'), 1)
            self.assertIn('slot->admitted || slot->cleared', text)
            self.assertIn('slots[4].done', text)
        self.assertNotEqual(header('missing-before'), header('baseline'))
        self.assertNotEqual(header('outside-reply'), header('baseline'))
        with self.assertRaises(ValueError): header('unknown')

    def test_crash_and_oversize_are_not_mutation_detection(self):
        for result in (SimpleNamespace(returncode=1, stdout='', stderr=''),
                       SimpleNamespace(returncode=0, stdout='{}', stderr='warning'),
                       SimpleNamespace(returncode=0, stdout='x' * 2000001, stderr='')):
            with self.assertRaises(ValueError): decode(result, {})


if __name__ == '__main__': unittest.main()
