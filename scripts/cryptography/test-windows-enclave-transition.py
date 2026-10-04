"""Transition measurement validators; native execution is a separate campaign."""
import copy
import unittest

from windows_enclave_transition_model import words, classify, validate


def fixture(seed=90, avx=0):
    return dict(scheduler=dict(events=[[1, 4, e] for e in (2, 3, 4)]), before=words(seed, avx), count=3,
                callbacks=[dict(event=e, count=e-1, registers=['other'] * 27) for e in (2, 3, 4)])


class Tests(unittest.TestCase):
    def test_patterns_and_classification(self):
        for seed in (90, 165):
            for avx in (0, 1):
                self.assertEqual(classify(words(seed, avx), seed, avx), ['pattern'] * 27)
                self.assertEqual(classify([0] * 75, seed, avx), ['zero'] * 27)
                validate(fixture(seed, avx), seed, avx)

    def test_before_omission_and_poison_omission(self):
        for field in range(75):
            value = fixture(90, 1)
            value['before'][field] ^= 1
            with self.assertRaisesRegex(ValueError, 'before-pattern measurement'): validate(value, 90, 1)

    def test_partial_patterns_are_not_hidden_by_other_register_bytes(self):
        for seed in (90, 165):
            for register in range(27):
                width = 32 if register < 16 else 8
                for offset in range(width - 3):
                    raw = bytearray(600)
                    start = register * 32 if register < 16 else 512 + (register - 16) * 8
                    raw[start + offset:start + offset + 4] = bytes([seed]) * 4
                    values = [int.from_bytes(raw[i:i+8], 'little') for i in range(0, 600, 8)]
                    self.assertEqual(classify(values, seed, 1)[register], 'pattern')
        values = [0] * 75
        values[2] = int.from_bytes(b'Z' * 8, 'little')
        self.assertEqual(classify(values, 90, 0)[0], 'zero')
        self.assertEqual(classify(values, 90, 1)[0], 'pattern')

    def test_independent_counts_order_and_shape(self):
        original = fixture()
        mutants = []
        for count in (True, -1, 0, 2, 4):
            value = copy.deepcopy(original); value['count'] = count; mutants.append(value)
        value = copy.deepcopy(original); value['callbacks'].reverse(); mutants.append(value)
        value = copy.deepcopy(original); value['callbacks'].pop(); mutants.append(value)
        for field, change in (('count', True), ('event', 1), ('registers', ['zero'] * 19), ('registers', ['unknown'] * 27)):
            value = copy.deepcopy(original); value['callbacks'][0][field] = change; mutants.append(value)
        for value in mutants:
            with self.assertRaises(ValueError): validate(value, 90, 0)

    def test_no_assumption_about_transition_result(self):
        for kind in ('pattern', 'zero', 'other'):
            value = fixture()
            for callback in value['callbacks']: callback['registers'] = [kind] * 27
            validate(value, 90, 0)

    def test_empty_control_does_not_claim_execution(self):
        value = dict(scheduler=dict(events=[]), before=[0]*75, count=0, callbacks=[])
        validate(value, 90, 0)
        value['before'] = words(90, 0)
        with self.assertRaises(ValueError): validate(value, 90, 0)

    def test_reject_bad_identities_and_words(self):
        for seed, avx in ((True, 0), (0, 0), (90, True), (90, 2)):
            with self.assertRaises(ValueError): words(seed, avx)
        for value in ([0]*74, [0]*76, [True]*75, [-1]*75, [1<<64]*75):
            with self.assertRaises(ValueError): classify(value, 90, 0)


if __name__ == '__main__': unittest.main()
