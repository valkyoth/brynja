"""Negative controls for the Poly1305 linked-verifier fingerprint."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('screen', Path(__file__).with_name('check-poly1305-linked.py'))
screen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(screen)


def fixture(slot=0x900, target=0x300, branch=0x209, width=32, wrapper=0x200):
    assembly = ['fixture\tfile format elf64-x86-64',
                f'100 <{screen.WRAPPER}>:', f' 100: callq 0x{wrapper:x}']
    for i, name in enumerate(screen.BODIES, 2):
        addr = i * 0x100
        assembly.append(f'{addr:x} <{name}>:')
        if name == screen.VERIFY:
            assembly.extend([f' 200: callq *0x10(%rip) # 0x{slot:x}',
                             f' 206: jne 0x{branch:x}', ' 208: retq'])
        else:
            assembly.extend([f' {addr:x}: movl ${width}, %edi', f' {addr+5:x}: retq'])
    reloc = f'{slot:x} R_X86_64_RELATIVE *ABS*+0x{target:x}'
    return screen.elf.Image('\n'.join(assembly), reloc)


class LinkedControls(unittest.TestCase):
    def test_got_address_is_not_the_target_identity(self):
        baseline = screen.fingerprint(fixture())
        self.assertEqual(baseline, screen.fingerprint(fixture(slot=0xa00)))
        self.assertNotEqual(baseline, screen.fingerprint(fixture(target=0x400)))
        with self.assertRaisesRegex(ValueError, 'unresolved RIP operand'):
            screen.fingerprint(fixture(target=0xfff))

    def test_changed_branch_or_clear_width_is_not_accepted(self):
        baseline = screen.fingerprint(fixture())
        for change in ({'branch': 0x208}, {'width': 16}):
            with self.subTest(change=change):
                self.assertNotEqual(baseline, screen.fingerprint(fixture(**change)))

    def test_wrapper_must_call_the_reviewed_verifier(self):
        with self.assertRaisesRegex(ValueError, 'does not call'):
            screen.fingerprint(fixture(wrapper=0x300))


if __name__ == '__main__':
    unittest.main()
