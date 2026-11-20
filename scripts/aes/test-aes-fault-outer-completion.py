#!/usr/bin/env python3
"""Outer-completion runner tests; mock transcripts are not fault evidence."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'outer_probe', Path(__file__).with_name('check-aes-fault-outer-completion.py'))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def transcript(width, path, case):
    markers = ['OUTER_CAPTURE 1', 'OUTER_ENTRY 1', 'OUTER_INNER_RETURN 1']
    if case != 'baseline':
        markers.append('OUTER_MUTATED 1')
    markers.append('OUTER_RETURN 1')
    if case == 'late-key-plus-result-bypass':
        markers.append('OUTER_FORGED 1')
    return '\n'.join([
        P.R.C.identity(width, path, 'baseline', 'ephemeral'),
        'BRYNJA_EPHEMERAL_EVIDENCE_CFG=false',
        f'BRYNJA_EPHEMERAL_CASE={width}:{path}',
        *[f'Hardware assisted breakpoint {n} at 0x1' for n in range(1, 5)],
        *[f'hit Breakpoint {n}, 0x1' for n in range(1, 5)],
        *markers, 'BRYNJA_EPHEMERAL_STORAGE_CLEARED',
        'BRYNJA_EPHEMERAL_' + ('ACCEPTED' if case == 'baseline' else 'REJECTED_RETIRED'),
        'test result: ok. 1 passed; 0 failed; 0 ignored;',
        'exited normally',
    ])


class OuterCompletionRunner(unittest.TestCase):
    def test_exact_cases_and_outcomes(self):
        for width in P.R.C.ANSWERS:
            for path in P.R.C.PATHS:
                for case in P.CASES:
                    good = transcript(width, path, case)
                    P.validate(good, width, path, case)
                    for marker in ('OUTER_CAPTURE 1', 'OUTER_INNER_RETURN 1',
                                   'OUTER_RETURN 1'):
                        with self.assertRaises(ValueError):
                            P.validate(good.replace(marker, marker[:-1]+'0'), width, path, case)
                    for old, new in (
                        ('EVIDENCE_CFG=false', 'EVIDENCE_CFG=true'),
                        ('hit Breakpoint', 'missed Breakpoint'),
                        ('test result: ok.', 'test result: FAILED.'),
                        ('exited normally', 'exited abnormally'),
                        ('_ACCEPTED', '_REJECTED_RETIRED') if case == 'baseline'
                        else ('_REJECTED_RETIRED', '_ACCEPTED'),
                    ):
                        with self.assertRaises(ValueError):
                            P.validate(good.replace(old, new), width, path, case)

    def test_mutation_and_forgery_happen_after_successful_inner_result(self):
        compute = dict(symbol=P.EPHEMERAL, ret=123)
        retained = dict(symbol=P.RETAINED, ret=456)
        for case in P.CASES:
            commands, test = P.commands(16, 'public', case, P.R.CAPTURE,
                                        compute, retained)
            self.assertEqual(test, P.R.C.identity(16, 'public', 'baseline', 'ephemeral'))
            self.assertEqual(sum(c.startswith('hbreak ') for c in commands), 4)
            inner = next(i for i, c in enumerate(commands)
                         if c.startswith('printf "OUTER_INNER_RETURN'))
            mutate = [i for i, c in enumerate(commands)
                      if c == 'set *$key = *$key ^ 1']
            self.assertEqual(len(mutate), int(case != 'baseline'))
            if mutate:
                self.assertLess(inner, mutate[0])
            self.assertEqual('set $al = 0' in commands,
                             case == 'late-key-plus-result-bypass')

    def test_invalid_case_and_missing_record_reject(self):
        with self.assertRaises(ValueError):
            P.commands(16, 'public', 'unknown', '', {}, {})
        for case in P.CASES:
            with self.assertRaises(ValueError):
                P.validate('', 16, 'public', case)

    def test_main_requires_complete_matrix_and_unchanged_artifact(self):
        elf = bytearray(32)
        elf[:6], elf[18:20] = b'\x7fELF\x02\x01', b'\x3e\x00'
        for changed in (False, True):
            runs = [subprocess.CompletedProcess(['objdump'], 0, 'dump', '')]
            runs += [subprocess.CompletedProcess(['gdb'], 0,
                     transcript(width, 'public', case), '')
                     for width in P.R.C.ANSWERS for case in P.CASES]
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch('sys.argv', ['probe', '--binary', 'fixture', '--path', 'public']), \
                 patch.object(Path, 'resolve', return_value=Path('/fixture')), \
                 patch.object(Path, 'read_bytes', side_effect=[elf, elf+b'x' if changed else elf]), \
                 patch.object(P.subprocess, 'run', side_effect=runs) as run, \
                 patch.object(P.R, 'symbol', side_effect=[P.R.CAPTURE, P.EPHEMERAL, P.RETAINED]), \
                 patch.object(P.R.C.P.TX, 'body', side_effect=[
                     dict(symbol=P.EPHEMERAL, ret=123),
                     dict(symbol=P.RETAINED, ret=456)]), \
                 redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(P.main(), 2 if changed else 0)
            self.assertEqual(run.call_count, 1 + len(P.R.C.ANSWERS) * len(P.CASES))
            self.assertEqual('DEVELOPMENT_OUTER_COMPLETION_OBSERVED' in stdout.getvalue(),
                             not changed)
            self.assertNotIn('dump', stdout.getvalue() + stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
