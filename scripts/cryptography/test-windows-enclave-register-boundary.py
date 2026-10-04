"""Non-native validation tests; these never substitute for register observations."""
import copy
import json
import subprocess
import unittest

import windows_enclave_register_boundary as model


def observation(case):
    wrapper, isa, admission, seed, restore = case
    width = 32 if isa == 'avx' else 16
    sentinel = bytes([seed if admission == 'admit' else 0] * width).hex()
    result = 91 if restore == 'restore-ok' else (0 if wrapper == 'sequential' else (1 << 64) - 1)
    return dict(wrapper=wrapper, isa=isa, admission=admission, seed=seed, result=result, restore=restore,
                body_calls=int(admission == 'admit'), finish_calls=1,
                finish=[bytes(width).hex()] * 6, returned=[bytes(width).hex()] * 6,
                body=[sentinel] * 6, restore_poison=[bytes([seed] * width).hex()] * 6,
                nonvolatile=[(bytes([seed] * 16) + bytes(width - 16)).hex()] * 10,
                rbx=int.from_bytes(bytes([seed] * 8), 'little'), gpr=[0] * 6)


class RegisterBoundaryTests(unittest.TestCase):
    def test_exact_population(self):
        self.assertEqual(len(set(model.CASES)), 32)
        for case in model.CASES:
            value = observation(case)
            self.assertEqual(model.validate(value, case), value)

    def test_every_snapshot_byte_is_required(self):
        for case in model.CASES:
            value = observation(case)
            for field in ('body', 'restore_poison', 'finish', 'returned', 'nonvolatile'):
                for reg in range(len(value[field])):
                    for byte in range(len(value[field][reg]) // 2):
                        changed = copy.deepcopy(value)
                        raw = bytearray.fromhex(changed[field][reg])
                        raw[byte] ^= 1
                        changed[field][reg] = raw.hex()
                        with self.assertRaisesRegex(ValueError, 'boundary mismatch'):
                            model.validate(changed, case)

    def test_no_vacuous_missing_wrong_count_or_relabelled_case(self):
        for case in model.CASES:
            value = observation(case)
            for field in model.FIELDS:
                changed = copy.deepcopy(value)
                del changed[field]
                with self.assertRaises(ValueError): model.validate(changed, case)
            for field in ('result', 'body_calls', 'finish_calls', 'seed', 'rbx'):
                for replacement in (-1, True, None):
                    with self.assertRaises(ValueError):
                        model.validate({**value, field: replacement}, case)
            for field in ('body', 'restore_poison', 'finish', 'returned', 'nonvolatile', 'gpr'):
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
            self.assertIn('.savexmm128 xmm' + str(reg), asm)
            self.assertIn('vinsertf128 ymm' + str(reg), asm)

    def test_all_wrappers_share_exact_guarded_cleanup(self):
        sources = [(model.SOURCE / name).read_text() for name in
                   ('window_rust_x64.asm', 'window_guard_x64.asm', 'concurrent_stack_x64.asm')]
        macros = [s[s.index('BRYNJA_REGISTER_SETUP MACRO'):s.index('.code')] for s in sources]
        self.assertEqual(macros[0], macros[1])
        self.assertEqual(macros[0], macros[2])
        for source in sources:
            self.assertEqual(source.count('    BRYNJA_REGISTER_CLEAR 0, 1'), 1)
            self.assertEqual(source.count('    BRYNJA_REGISTER_CLEAR 1, 0'), 1)
            self.assertEqual(source.count('    BRYNJA_REGISTER_SETUP\n'), 1)
            self.assertLess(source.index('    BRYNJA_REGISTER_SETUP\n'), source.index('    call __chkstk'))
            self.assertLess(source.index('    cmp ecx, 01c000000h'), source.index('    xgetbv'))
            self.assertLess(source.index('    cmp eax, 6'), source.index('    mov QWORD PTR [rbp + 32], 1'))
            self.assertIn('    cmp QWORD PTR [rbp + 32], 0\n    je baseline\n    vzeroupper', source)
            self.assertIn('    mov r10, rbx', source)
            self.assertIn('    mov rbx, r10\n    xor r10d, r10d', source)
            self.assertNotIn('mov [rbp + 40], rbx', source)
            for reg in range(6, 16):
                self.assertNotIn('pxor xmm' + str(reg), source)


if __name__ == '__main__':
    unittest.main()
