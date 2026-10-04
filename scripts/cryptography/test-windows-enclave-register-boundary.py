"""Non-native validation tests; these never substitute for register observations."""
import copy
import json
import subprocess
import unittest

import windows_enclave_register_boundary as model


def observation(case):
    wrapper, isa, admission, seed = case
    width = 32 if isa == 'avx' else 16
    sentinel = bytes([seed if admission == 'admit' else 0] * width).hex()
    return dict(wrapper=wrapper, isa=isa, admission=admission, seed=seed, result=91,
                body_calls=int(admission == 'admit'), finish_calls=1,
                finish=[sentinel] * 6, returned=[sentinel] * 6)


class RegisterBoundaryTests(unittest.TestCase):
    def test_exact_population(self):
        self.assertEqual(len(set(model.CASES)), 16)
        for case in model.CASES:
            value = observation(case)
            self.assertEqual(model.validate(value, case), value)

    def test_every_snapshot_byte_is_required(self):
        for case in model.CASES:
            value = observation(case)
            for field in ('finish', 'returned'):
                for reg in range(6):
                    for byte in range(len(value[field][reg]) // 2):
                        changed = copy.deepcopy(value)
                        raw = bytearray.fromhex(changed[field][reg])
                        raw[byte] ^= 1
                        changed[field][reg] = raw.hex()
                        with self.assertRaisesRegex(ValueError, 'characterization changed'):
                            model.validate(changed, case)

    def test_no_vacuous_missing_wrong_count_or_relabelled_case(self):
        for case in model.CASES:
            value = observation(case)
            for field in model.FIELDS:
                changed = copy.deepcopy(value)
                del changed[field]
                with self.assertRaises(ValueError): model.validate(changed, case)
            for field in ('result', 'body_calls', 'finish_calls', 'seed'):
                for replacement in (-1, True, None):
                    with self.assertRaises(ValueError):
                        model.validate({**value, field: replacement}, case)
            for field in ('finish', 'returned'):
                for replacement in ([], value[field][:-1], value[field] * 2):
                    with self.assertRaises(ValueError):
                        model.validate({**value, field: replacement}, case)
            with self.assertRaises(ValueError):
                model.validate({**value, 'whole_image_qualified': True}, case)
            other = model.CASES[(model.CASES.index(case) + 1) % len(model.CASES)]
            with self.assertRaises(ValueError): model.validate(value, other)

    def test_crash_unsupported_stderr_invalid_duplicate_and_oversized(self):
        case = model.CASES[0]
        text = json.dumps(observation(case))
        good = subprocess.CompletedProcess([], 0, text, '')
        self.assertEqual(model.decode(good, case), observation(case))
        for code, stdout, stderr in (
            (3, text, ''), (0xc0000005, text, ''), (1, text, ''),
            (0, text, 'warning'), (0, '', ''), (0, '[' + text + ']', ''),
            (0, text + 'x' * 8192, ''), (0, text[:-1] + ',"seed":90}', '')):
            with self.assertRaises(ValueError):
                model.decode(subprocess.CompletedProcess([], code, stdout, stderr), case)

    def test_stub_scope_and_abi(self):
        asm = (model.SOURCE / 'register_boundary_probe.asm').read_text()
        c = (model.SOURCE / 'register_boundary_probe.c').read_text()
        for token in ('call PublicStackFrame', 'call PublicLockedFrame',
                      'SNAPSHOT ProbeFinish', 'SNAPSHOT ProbeReturn'):
            self.assertIn(token, asm)
        self.assertIn('IsProcessorFeaturePresent(PF_AVX_INSTRUCTIONS_AVAILABLE)', c)
        self.assertNotIn('CallEnclave(', c)
        self.assertNotIn('vzeroall', asm)
        for reg in range(6, 16):
            self.assertNotIn('xmm' + str(reg), asm)
            self.assertNotIn('ymm' + str(reg), asm)


if __name__ == '__main__':
    unittest.main()
