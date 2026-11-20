#!/usr/bin/env python3
"""Design sanity checks only: toy counterexamples, NOT AES/fault qualification.

These tests exercise reasoning in aes-fault-profile-design.md. They neither
implement the proposed profile nor establish machine-code/SIFA resistance.
All values are public fixtures. No release gate or verifier pass is registered.
"""
from functools import reduce
from operator import xor
import unittest


def suffix(value):
    """A toy byte permutation, not an AES round."""
    return (5 * value + 7) % 256


def fold(values):
    return reduce(xor, values, 0)


class FaultModelSanityTests(unittest.TestCase):
    def test_one_changed_state_and_same_bijective_suffix_changes_output(self):
        self.assertEqual(len({suffix(x) for x in range(256)}), 256)
        for original in range(256):
            for replacement in range(256):
                self.assertEqual(suffix(original) == suffix(replacement),
                                 original == replacement)

    def test_skipping_a_bijection_can_be_ineffective(self):
        rotate = lambda x: ((x << 1) | (x >> 7)) & 255
        self.assertEqual(len({rotate(x) for x in range(256)}), 256)
        self.assertEqual(rotate(0), 0)
        self.assertEqual(rotate(255), 255)
        self.assertNotEqual(rotate(1), 1)
        # Bijection alone cannot prove that every skipped step changes output.

    def test_changes_to_multiple_round_keys_need_a_separate_argument(self):
        # Toy two-round cipher: each round is bijective. Correlated schedule
        # changes cancel. This is NOT a claimed AES key-schedule collision.
        key_a, key_b, delta = 0x34, 0x71, 0x80
        for value in range(256):
            self.assertEqual((value ^ key_a) ^ key_b,
                             (value ^ (key_a ^ delta)) ^ (key_b ^ delta))

    def test_correct_output_or_alarm_is_an_equality_oracle(self):
        for intermediate in range(256):
            successful_replacements = [v for v in range(256)
                                       if suffix(v) == suffix(intermediate)]
            self.assertEqual(successful_replacements, [intermediate])
        # Correct-output integrity does not establish confidentiality.

    def test_retirement_does_not_limit_ineffective_queries(self):
        intermediate = 0x43
        terminal = False
        for _ in range(10):
            self.assertFalse(terminal)
            replacement = intermediate
            terminal = suffix(replacement) != suffix(intermediate)
        self.assertFalse(terminal)
        terminal = suffix(intermediate ^ 1) != suffix(intermediate)
        self.assertTrue(terminal)
        # Recreating this local state cannot enforce global key retirement.

    def test_nonzero_xor_at_state_boundary_has_value_independent_alarm(self):
        # ONLY the unchanged bijective suffix premise makes this claim valid.
        for delta in range(1, 256):
            alarms = [suffix(x ^ delta) != suffix(x) for x in range(256)]
            self.assertEqual(alarms, [True] * 256)

    def test_xor_inside_circuit_can_have_value_dependent_propagation(self):
        # A flipped internal operand followed by AND with a secret bit.
        # This is not the boundary of an unchanged permutation suffix.
        for operand in (0, 1):
            alarms = [((operand ^ 1) & bit) != (operand & bit)
                      for bit in (0, 1)]
            self.assertEqual(alarms, [False, True])

    def test_stuck_at_masks_filter_correct_outputs(self):
        for mutate, retained_bit in ((lambda x: x & 0xfe, 0),
                                     (lambda x: x | 1, 1)):
            survivors = [x for x in range(256)
                         if suffix(mutate(x)) == suffix(x)]
            self.assertEqual(len(survivors), 128)
            self.assertEqual({x & 1 for x in survivors}, {retained_bit})
            # All survivors have correct outputs, yet their selection leaks.

    def test_global_retirement_stops_at_first_effective_fault(self):
        def observations(secret, replacements):
            transcript = []
            for value in replacements:
                alarm = suffix(value) != suffix(secret)
                transcript.append(alarm)
                if alarm:
                    break  # Global retirement, not recreation of local state.
            return transcript

        self.assertEqual(observations(7, [7, 7, 8, 7]), [False, False, True])
        self.assertEqual(observations(7, [8, 7]), [True])
        # A fresh key can give a different relation at the same site. Its
        # observations cannot be treated as more guesses about the old byte.
        self.assertEqual(observations(8, [8, 7]), [False, True])

    def test_same_error_value_does_not_hide_failure_stage(self):
        def checks(failure_stage):
            work = 0
            for stage in range(4):
                work += 1
                if stage == failure_stage:
                    return 'fault', work
            return 'ok', work

        outcomes = [checks(stage) for stage in range(4)]
        self.assertEqual({error for error, _ in outcomes}, {'fault'})
        self.assertEqual({work for _, work in outcomes}, {1, 2, 3, 4})
        # Logical work only: this is not a timing experiment or padding design.

    def test_persistent_constant_fault_can_preserve_some_correct_outputs(self):
        # Two toy permutations with a changed persistent odd multiplier.
        # Not an AES PFA claim: output agreement alone cannot attest constants.
        correct = lambda x: x
        faulty = lambda x: (3 * x) % 256
        self.assertEqual(len({faulty(x) for x in range(256)}), 256)
        survivors = [x for x in range(256) if correct(x) == faulty(x)]
        self.assertEqual(survivors, [0, 128])
        # Exercise each domain with one independent validation path bypassed.
        # Comparison protects released values, not the constants themselves.
        for fault_in_primary in (False, True):
            for bypass in (0, 1):
                released = []
                for value in range(256):
                    primary, secondary = correct(value), faulty(value)
                    if fault_in_primary:
                        primary, secondary = secondary, primary
                    first = primary == secondary
                    second = secondary == primary
                    if (first or bypass == 0) and (second or bypass == 1):
                        self.assertEqual(primary, correct(value))
                        released.append(value)
                self.assertEqual(released, survivors)
        # Logical comparisons only, not independent compiled checks or proof
        # of detection on every use; the two surviving inputs remain filtered.

    def test_persistent_constant_retires_only_after_detected_mismatch(self):
        terminal = False
        computations = 0

        def operation(value):
            nonlocal terminal, computations
            if terminal:
                return 'terminal', None
            computations += 1
            primary, secondary = (3 * value) % 256, value
            if primary != secondary:
                terminal = True
                return 'fault', None
            return 'ok', primary

        # A single persistent fault survives multiple correct-output calls.
        for value in (0, 128, 0, 128):
            self.assertEqual(operation(value), ('ok', value))
            self.assertFalse(terminal)
        self.assertEqual(operation(1), ('fault', None))
        self.assertTrue(terminal)
        self.assertEqual(operation(0), ('terminal', None))
        self.assertEqual(computations, 5)  # No retry or dispatch after detection.

    def test_uniform_errors_do_not_hide_terminal_availability(self):
        def peer_response(outcome):
            return 'success' if outcome == 'ok' else 'failure'

        self.assertEqual({peer_response(outcome) for outcome in
                          ('fault', 'terminal', 'other-error')}, {'failure'})
        # Even with no distinct error or exposed diagnostic, a later request
        # that would succeed on a healthy owner fails on a retired owner.
        self.assertNotEqual(peer_response('ok'), peer_response('terminal'))
        # This mapping alone is not remote-oracle or timing resistance.

    def test_correlated_skip_can_pass_agreement_with_plaintext_echo(self):
        # Deliberately out of budget. Do not turn this into echo rejection.
        input_value = 1
        correct = suffix(input_value)
        primary = secondary = destination = input_value
        self.assertEqual(primary, secondary)
        self.assertEqual(destination, primary)
        self.assertEqual(destination, secondary)
        self.assertNotEqual(destination, correct)

    def test_correlated_decrypt_skip_can_return_ciphertext_as_plaintext(self):
        inverse = lambda x: ((x - 7) * 205) % 256
        for plaintext in range(256):
            ciphertext = suffix(plaintext)
            self.assertEqual(inverse(ciphertext), plaintext)
            # Two skipped toy domains agree on unchanged ciphertext. A clearing
            # owner would not repair this incorrect value; this is out of budget.
            primary = secondary = destination = ciphertext
            self.assertEqual(destination, primary)
            self.assertEqual(destination, secondary)
            if ciphertext != plaintext:
                self.assertNotEqual(destination, inverse(ciphertext))

    def test_each_readback_path_must_compare_both_domains(self):
        good = bytes(range(16))

        def paired_readbacks(destination, primary, secondary, bypass):
            # Functional pairing only, NOT independent machine-code checks.
            first = (destination == primary and destination == secondary)
            second = (destination == secondary and destination == primary)
            return (first or bypass == 0) and (second or bypass == 1)

        for bypass in (None, 0, 1):
            self.assertTrue(paired_readbacks(good, good, good, bypass))
        for position in range(16):
            for delta in range(1, 256):
                corrupted = bytearray(good)
                corrupted[position] ^= delta
                bad = bytes(corrupted)
                # A single primary event propagates into the destination.
                # Split pairing would accept if the secondary check is skipped.
                split_primary_check = bad == bad
                bypassed_secondary_check = True
                self.assertTrue(split_primary_check and bypassed_secondary_check)
                for bypass in (None, 0, 1):
                    for destination, primary, secondary in (
                            (bad, bad, good),   # D1 primary, then copy.
                            (good, good, bad),  # D1 secondary.
                            (bad, good, good)):  # D4 destination.
                        self.assertFalse(paired_readbacks(
                            destination, primary, secondary, bypass))

    def test_one_loaded_value_broadcast_to_two_replicas_hides_corruption(self):
        source = 0x25
        corrupted_load = source ^ 0x80
        primary, secondary = corrupted_load, corrupted_load
        self.assertEqual(primary, secondary)
        self.assertNotEqual(primary, source)
        independent_primary, independent_secondary = source ^ 0x80, source
        self.assertNotEqual(independent_primary, independent_secondary)

    def test_xor_fold_is_not_a_full_equality_check(self):
        left = bytes(16)
        right = bytes([0x55, 0x55] + [0] * 14)
        self.assertNotEqual(left, right)
        self.assertEqual(fold(a ^ b for a, b in zip(left, right)), 0)

    def test_expanding_one_corrupted_decision_does_not_protect_its_origin(self):
        full = (1 << 128) - 1
        correct_decision = 0
        corrupted_decision = correct_decision ^ 1
        self.assertEqual((-correct_decision) & full, 0)
        self.assertEqual((-corrupted_decision) & full, full)

    def test_complement_encoding_detects_common_zero_but_not_common_xor(self):
        for original in range(256):
            primary, secondary = original, original ^ 255
            self.assertEqual(primary, secondary ^ 255)
            self.assertNotEqual(0, 0 ^ 255)  # Both physical stores cleared.
            for delta in (1, 0x55, 0xff):
                corrupted_primary = primary ^ delta
                corrupted_secondary = secondary ^ delta
                self.assertEqual(corrupted_primary, corrupted_secondary ^ 255)
                self.assertNotEqual(corrupted_primary, original)

    def test_example_codewords_reject_all_single_byte_replacements(self):
        # Illustration only; these are NOT selected production encodings.
        words = [bytes([v]) * 16 for v in (0xa5, 0x3c, 0x5a)]
        self.assertNotIn(bytes(16), words)
        for left in words:
            for right in words:
                if left != right:
                    self.assertGreater(sum((a ^ b).bit_count()
                                           for a, b in zip(left, right)), 8)
            for position in range(16):
                for replacement in range(256):
                    if replacement == left[position]:
                        continue
                    changed = bytearray(left)
                    changed[position] = replacement
                    self.assertNotIn(bytes(changed), words)

    def test_valid_codeword_substitution_is_not_prevented_by_distance(self):
        terminal = bytes([0x5a]) * 16
        healthy = bytes([0xa5]) * 16
        self.assertNotEqual(terminal, healthy)
        overwritten = healthy  # Outside the single-byte model.
        self.assertEqual(overwritten, healthy)
        # Encoding is neither authentication nor control-flow protection.


if __name__ == '__main__':
    unittest.main()
