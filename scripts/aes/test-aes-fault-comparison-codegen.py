#!/usr/bin/env python3
"""Parser/template regression tests, not fault simulation of executable bytes."""
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout, redirect_stderr
import importlib.util
import io
from pathlib import Path
import subprocess
from types import SimpleNamespace
from aes_fault_comparison_codegen import EXPECTED, PREFIX, inspect

SPEC = importlib.util.spec_from_file_location('comparison_cli', Path(__file__).with_name('check-aes-fault-comparison-codegen.py'))
CLI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLI)


def fixture(arch):
    output = []
    for role, base in [('forward', 0x1000), ('reverse', 0x2000)]:
        output.append(f'{base:x} <{PREFIX}{role}>:')
        for index, operation in enumerate(EXPECTED[arch, role]):
            if '@' in operation:
                prefix, target = operation.split('@')
                operation = prefix + hex(base + int(target)*4)
            output.append(f' {base+index*4:x}: {operation}')
        output.append('')
    return '\n'.join(output)


class ComparisonObservation(unittest.TestCase):
    def test_exact_distinct_leaves(self):
        for arch in ('x86_64','aarch64'):
            result = inspect(fixture(arch),arch)
            self.assertEqual(set(result),{'forward','reverse'})
            self.assertNotEqual(result['forward']['sha256'],result['reverse']['sha256'])

    def test_every_omitted_instruction_rejected(self):
        for arch in ('x86_64','aarch64'):
            original = fixture(arch).splitlines()
            for index,line in enumerate(original):
                if line.startswith(' '):
                    with self.assertRaises(ValueError):
                        inspect('\n'.join(original[:index]+original[index+1:]),arch)

    def test_legacy_symbol_hashes_preserve_exact_and_duplicate_checks(self):
        for arch in ('x86_64','aarch64'):
            original = fixture(arch)
            hashed = original.replace('forward>', 'forward::h98b8c49c963cf725>').replace(
                'reverse>', 'reverse::h34a82ab8f57036e6>')
            self.assertEqual(inspect(hashed,arch),inspect(original,arch))
            for bad in [original+hashed, hashed.replace('h98b8c49c963cf725','hshort'),
                        hashed.replace('h98b8c49c963cf725','h98b8c49c963cf725extra')]:
                with self.assertRaises(ValueError): inspect(bad,arch)

    def test_wrong_operands_masks_and_control_rejected(self):
        cases = {
            'x86_64': [('(%r11,%rcx,1)','(%rbx,%rcx,1)'), ('cmp $0x10','cmp $0xf'),
                       ('xor %r9d,%r9d','xor %eax,%eax'), ('jne 0x2018','jne 0x1000'),
                       ('and %dl,%r9b','or %dl,%r9b')],
            'aarch64': [('[x3,x4]','[x2,x4]'), ('cmp x4,#0x10','cmp x4,#0xf'),
                        ('mov x5,xzr','mov x4,xzr'), ('cbnz x4,0x200c','cbnz x4,0x1000'),
                        ('and w7,w7,w6','orr w7,w7,w6')],
        }
        for arch, changes in cases.items():
            for old,new in changes:
                self.assertIn(old,fixture(arch))
                with self.assertRaises(ValueError): inspect(fixture(arch).replace(old,new,1),arch)

    def test_missing_duplicate_aliased_and_wrong_arch_rejected(self):
        for arch in ('x86_64','aarch64'):
            text = fixture(arch)
            for bad in ['',text.split('2000 <')[0],text+text,text.replace('2000 <','1000 <'),
                        text.replace('reverse>','forward>')]:
                with self.assertRaises(ValueError): inspect(bad,arch)
        with self.assertRaises(ValueError): inspect(fixture('x86_64'),'aarch64')
        with self.assertRaises(ValueError): inspect(fixture('x86_64'),'unknown')

    def test_inserted_call_and_unparsed_data_rejected(self):
        for arch in ('x86_64','aarch64'):
            for extra in [' 1fff: call memcmp', 'unparsed annotation']:
                with self.assertRaises(ValueError): inspect(fixture(arch)+'\n'+extra,arch)

    def test_following_generic_symbol_ends_selected_body(self):
        for arch in ('x86_64','aarch64'):
            text = fixture(arch)+'\n3000 <other::<u8>::function>:\n 3000: ret\n'
            self.assertEqual(set(inspect(text,arch)),{'forward','reverse'})

    def cli(self, data, results):
        output, errors = io.StringIO(), io.StringIO()
        with patch('sys.argv',['check','--arch','x86_64','--binary','fixture']), \
             patch.object(Path,'read_bytes',return_value=data), \
             patch.object(CLI.subprocess,'run',side_effect=results), \
             redirect_stdout(output), redirect_stderr(errors):
            status = CLI.main()
        return status, output.getvalue()

    def test_cli_requires_successful_tools_and_both_leaves(self):
        header = SimpleNamespace(stdout='architecture: i386:x86-64,')
        body = SimpleNamespace(stdout=fixture('x86_64'))
        status, text = self.cli(b'\x7fELFtest',[header,body])
        self.assertEqual(status,0)
        self.assertIn('OPAQUE_COMPARISON_LEAVES_OBSERVED',text)
        for responses in [[header,SimpleNamespace(stdout='')],
                          [SimpleNamespace(stdout='architecture: aarch64')],
                          [subprocess.CalledProcessError(1,['objdump'])],
                          [subprocess.TimeoutExpired(['objdump'],30)]]:
            status, text = self.cli(b'\x7fELFtest',responses)
            self.assertEqual(status,2)
            self.assertNotIn('OPAQUE_COMPARISON_LEAVES_OBSERVED',text)

    def test_non_elf_rejected_before_disassembler(self):
        status, text = self.cli(b'not ELF',[])
        self.assertEqual(status,2)
        self.assertNotIn('OPAQUE_COMPARISON_LEAVES_OBSERVED',text)


if __name__ == '__main__':
    unittest.main()
