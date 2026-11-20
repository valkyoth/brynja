#!/usr/bin/env python3
"""Regression tests for the optional development guard experiment runner."""
from contextlib import redirect_stdout, redirect_stderr
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('guard', Path(__file__).with_name('check-aes-fault-guard.py'))
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


def fixture():
    result = [f'1000 <{GUARD.SYMBOL}>:']
    for index, instruction in enumerate(GUARD.EXPECTED):
        if '@' in instruction:
            op, target = instruction.split('@')
            instruction = op + f'{0x1000 + 4 * int(target):x}'
        result.append(f' {0x1000+4*index:x}: {instruction}')
    return '\n'.join(result)


def transcript(count, negative=False):
    output = GUARD.TEST + '\n'
    for number in range(1, count+1):
        output += f'Hardware assisted breakpoint {number} at 0x123\n'
        output += f'Thread 2 hit Breakpoint {number}, 0x123\n'
        output += 'BRYNJA_GUARD_PRE 1 fffe\nBRYNJA_GUARD_APPLIED 1\n'
    if negative:
        output += 'test result: FAILED. 0 passed; 1 failed; 0 ignored;\n'
        output += 'left: [66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66]\n'
        output += 'exited with code 0145\n'
    else:
        output += 'test result: ok. 1 passed; 0 failed; 0 ignored;\nexited normally\n'
    return output


class GuardTests(unittest.TestCase):
    def test_exact_leaf_hash_suffix_and_following_generic_symbol(self):
        expected = (GUARD.SYMBOL, list(range(0,124,4)))
        self.assertEqual(GUARD.inspect(fixture()),expected)
        hashed = fixture().replace(GUARD.SYMBOL,GUARD.SYMBOL+'::h1234567890abcdef')
        self.assertEqual(GUARD.inspect(hashed)[1],expected[1])
        self.assertEqual(GUARD.inspect(fixture()+'\n2000 <other::<u8>>:\n 2000: ret'),expected)
        for bad in ['',fixture()+fixture(),hashed+fixture()]:
            with self.assertRaises(ValueError): GUARD.inspect(bad)

    def test_every_instruction_omission_and_guard_operand_changes_reject(self):
        lines = fixture().splitlines()
        for index in range(1,len(lines)):
            with self.assertRaises(ValueError):
                GUARD.inspect('\n'.join(lines[:index]+lines[index+1:]))
        for old,new in [('test %eax,%eax','test %r11d,%r11d'),
                        ('cmp $0xffff,%r11d','cmp $0x0,%r11d'),
                        ('(%rcx,%r9,1)','(%rdx,%r9,1)'),
                        ('jne 1064','jne 1058'),('xor %r11d,%r11d','nop')]:
            self.assertIn(old,fixture())
            with self.assertRaises(ValueError): GUARD.inspect(fixture().replace(old,new))

    def test_commands_use_hardware_stops_and_validate_mutations(self):
        for events in GUARD.CASES.values():
            commands = GUARD.commands(GUARD.SYMBOL,list(range(0,124,4)),events)
            self.assertEqual(sum(c.startswith('hbreak ') for c in commands),len(events))
            self.assertEqual(sum('BRYNJA_GUARD_APPLIED' in c for c in commands),len(events))
            self.assertFalse(any(c.startswith(('break ', 'set {')) for c in commands))
        with self.assertRaises(ValueError): GUARD.commands(GUARD.SYMBOL,list(range(0,124,4)),[(18,'invalid')])

    def test_transcript_requires_reachability_prestate_mutation_and_exact_outcome(self):
        for count in (0,1,2):
            GUARD.validate_transcript(transcript(count),count,False)
        GUARD.validate_transcript(transcript(2,True),2,True)
        good = transcript(1)
        for bad in [good.replace('Hardware assisted breakpoint','Breakpoint'),
                    good.replace('hit Breakpoint','missed Breakpoint'),
                    good.replace('PRE 1 fffe','PRE 0 fffe'),
                    good.replace('APPLIED 1','APPLIED 0'),
                    good.replace('1 passed','0 passed'),
                    good.replace('exited normally','SIGSEGV'),good+good]:
            with self.assertRaises(ValueError): GUARD.validate_transcript(bad,1,False)
        with self.assertRaises(ValueError): GUARD.validate_transcript(transcript(2),2,True)
        with self.assertRaises(ValueError): GUARD.validate_transcript(transcript(2,True).replace('66','145'),2,True)

    def test_cli_errors_never_print_success_marker(self):
        elf = bytearray(32)
        elf[:6] = b'\x7fELF\x02\x01'
        elf[18:20] = b'\x3e\x00'
        for data, error in [(b'bad',AssertionError('must not invoke tool')),
                            (elf,subprocess.TimeoutExpired(['objdump'],30)),
                            (elf,subprocess.CalledProcessError(1,['objdump']))]:
            output = io.StringIO()
            with patch('sys.argv',['guard','--binary','fixture']), \
                 patch.object(Path,'resolve',return_value=Path('/fixture')), \
                 patch.object(Path,'read_bytes',return_value=data), \
                 patch.object(GUARD.subprocess,'run',side_effect=error), \
                 redirect_stdout(output), redirect_stderr(io.StringIO()):
                self.assertEqual(GUARD.main(),2)
            self.assertNotIn('DEVELOPMENT_GUARD_EXPERIMENT_OBSERVED',output.getvalue())


if __name__ == '__main__':
    unittest.main()
