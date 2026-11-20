#!/usr/bin/env python3
"""Retained-state runner tests; mock transcripts are not native fault evidence."""
from contextlib import redirect_stdout, redirect_stderr
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'retained_probe', Path(__file__).with_name('check-aes-fault-retained.py'))
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)


def transcript(width, path, owner, case):
    prefix = 'BRYNJA_'+owner.upper()
    markers = ['RETAINED_CAPTURE 1', 'RETAINED_WINDOW 1']
    if case.startswith('secondary-schedule') or case == 'secondary-rounds-after':
        markers += ['RETAINED_LAYOUT 1']
    if case.endswith('-after'):
        markers += ['RETAINED_RETURN 1']
    if case != 'baseline':
        markers += ['RETAINED_MUTATED 1']
    if case == 'input-capture':
        markers = ['RETAINED_INPUT 1', 'RETAINED_FIRST_COPY 1',
                   'RETAINED_MUTATED 1', 'RETAINED_SECOND_COPY 1']
    stops = 3 if case.endswith('-after') else 2
    hits = 3 if case == 'input-capture' else stops
    return '\n'.join([
        R.C.identity(width, path, 'baseline', owner),
        prefix+'_EVIDENCE_CFG=false', f'{prefix}_CASE={width}:{path}',
        *[f'Hardware assisted breakpoint {n+1} at 0x1' for n in range(stops)],
        *[f'hit Breakpoint {min(n+1, stops)}, 0x1' for n in range(hits)], *markers,
        prefix+'_STORAGE_CLEARED', prefix+('_ACCEPTED' if case == 'baseline' else '_REJECTED_RETIRED'),
        'test result: ok. 1 passed; 0 failed; 0 ignored;', 'exited normally',
    ])


class RetainedRunner(unittest.TestCase):
    def test_execution_failure_reports_only_checkpoint_counts(self):
        good = transcript(16, 'public', 'cached', 'baseline')
        bad = good.replace('hit Breakpoint', 'missed Breakpoint', 1)
        with self.assertRaisesRegex(ValueError, r'^retained native execution unconfirmed: checks='):
            R.validate(bad, 16, 'public', 'cached', 'baseline')

    def test_symbol_lookup_handles_both_demanglers_and_rejects_ambiguity(self):
        name = R.TRANSFORM
        parent, method = name.rsplit('::', 1)
        for candidate in (name, '<'+parent+'>::'+method):
            for suffix in ('', '::h1234567890abcdef'):
                dump = f'1234 <{candidate+suffix}>:\n'
                self.assertEqual(R.symbol(dump, name), candidate+suffix)
                with self.assertRaises(ValueError):
                    R.symbol(dump+dump, name)
        with self.assertRaises(ValueError):
            R.symbol('', name)
        with self.assertRaises(ValueError):
            R.symbol(f'1234 <{name}_other>:\n', name)

    def test_all_cases_require_exact_identity_events_and_outcome(self):
        for width in R.C.ANSWERS:
            for path in R.C.PATHS:
                for owner in R.C.OWNERS:
                    for case in R.CASES:
                        good = transcript(width, path, owner, case)
                        R.validate(good, width, path, owner, case)
                        R.validate(good.replace('\n', '\r\n'), width, path, owner, case)
                        for line in good.splitlines():
                            if line.startswith(('RETAINED_', 'BRYNJA_')):
                                for bad in ('missing', line+' extra', line+'\n'+line):
                                    with self.assertRaises(ValueError):
                                        R.validate(good.replace(line, bad, 1), width, path, owner, case)
                            if line.startswith('RETAINED_'):
                                with self.assertRaises(ValueError):
                                    R.validate(good.replace(line, line[:-1]+'0'), width, path, owner, case)
                        for old, new in (
                            ('EVIDENCE_CFG=false', 'EVIDENCE_CFG=true'),
                            ('Hardware assisted breakpoint', 'Breakpoint'),
                            ('hit Breakpoint', 'missed Breakpoint'),
                            ('test result: ok.', 'test result: FAILED.'),
                            ('exited normally', 'exited abnormally'),
                        ):
                            with self.assertRaises(ValueError):
                                R.validate(good.replace(old, new), width, path, owner, case)
                        for other in R.C.OWNERS:
                            if other != owner:
                                with self.assertRaises(ValueError):
                                    R.validate(good, width, path, other, case)
                        a, b = 'BRYNJA_'+owner.upper()+'_ACCEPTED', 'BRYNJA_'+owner.upper()+'_REJECTED_RETIRED'
                        wrong = good.replace(a, b) if case == 'baseline' else good.replace(b, a)
                        with self.assertRaises(ValueError):
                            R.validate(wrong, width, path, owner, case)

    def test_injection_sites_are_after_capture_and_before_or_after_secondary_work(self):
        for width in R.C.ANSWERS:
            for path in R.C.PATHS:
                for owner in R.C.OWNERS:
                    for case in R.CASES:
                        commands, test = R.commands(width, path, owner, case, R.CAPTURE,
                                                    dict(symbol=R.TRANSFORM, ret=123), dict(symbol=R.COPY, ret=456))
                        self.assertEqual(test, R.C.identity(width, path, 'baseline', owner))
                        self.assertFalse(any(c.startswith('break ') for c in commands))
                        self.assertEqual('ignore 1 1' in commands, case == 'input-capture')
                        self.assertEqual(sum(c.startswith('hbreak ') for c in commands), 3 if case.endswith('-after') else 2)
                        self.assertLess(commands.index('disable 2'), commands.index('enable 2'))
                        if case == 'baseline':
                            self.assertFalse(any(c.startswith('set *') for c in commands))
                        self.assertEqual('set *$first = *$first ^ 1' in commands, case in ('primary-key', 'input-capture'))
                        self.assertEqual('set *$second = *$second ^ 1' in commands, case == 'secondary-key')
                        self.assertEqual('set *$rounds = *$rounds ^ 1' in commands, case == 'secondary-rounds-after')
                        self.assertEqual('set *$planes = *$planes ^ 1' in commands, case.startswith('secondary-schedule'))
                        if case.endswith('-after'):
                            self.assertLess(commands.index('disable 3'), commands.index('enable 3'))
                            self.assertTrue(any(c.startswith('printf "RETAINED_RETURN') and '$al == 0' in c and '$result' in c for c in commands))
                        if case == 'input-capture':
                            self.assertEqual(commands.count('disable 2'), 2)
                            self.assertTrue(any(c.startswith('printf "RETAINED_SECOND_COPY') and '$source' in c and '$first' in c and '$second' in c for c in commands))

    def test_unknown_experiments_and_invalid_extents_reject(self):
        for width, path, owner, case in ((15, 'public', 'cached', 'baseline'),
                                       (16, 'bad', 'cached', 'baseline'),
                                       (16, 'public', 'bad', 'baseline'),
                                       (16, 'public', 'cached', 'bad')):
            with self.assertRaises(ValueError):
                R.validate('', width, path, owner, case)
        for data in (b'', b'1', b'123456789'):
            with self.assertRaises(ValueError):
                R.bytes_at('$p', data)
        with self.assertRaises(ValueError):
            R.commands(16, 'public', 'cached', 'input-capture', R.CAPTURE,
                       dict(symbol=R.TRANSFORM, ret=123))

    def test_complete_matrix_and_unchanged_artifact_required(self):
        elf = bytearray(32)
        elf[:6], elf[18:20] = b'\x7fELF\x02\x01', b'\x3e\x00'
        for owner in R.C.OWNERS:
            for path in R.C.PATHS:
                for changed in (False, True):
                    runs = [subprocess.CompletedProcess(['objdump'], 0, 'dump', '')]
                    runs += [subprocess.CompletedProcess(['gdb'], 0, transcript(w, path, owner, c), '') for w in R.C.ANSWERS for c in R.CASES]
                    stdout = io.StringIO()
                    with patch('sys.argv', ['probe', '--binary', 'fixture', '--owner', owner, '--path', path]), \
                         patch.object(Path, 'resolve', return_value=Path('/fixture')), \
                         patch.object(Path, 'read_bytes', side_effect=[elf, elf+b'x' if changed else elf]), \
                         patch.object(R.subprocess, 'run', side_effect=runs) as run, \
                         patch.object(R, 'symbol', side_effect=[R.CAPTURE, R.TRANSFORM, R.COPY]), \
                         patch.object(R.C.P.TX, 'body', return_value=dict(symbol=R.TRANSFORM, ret=123)), \
                         redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                        self.assertEqual(R.main(), 2 if changed else 0)
                        self.assertEqual(run.call_count, 1+len(R.C.ANSWERS)*len(R.CASES))
                    self.assertEqual('DEVELOPMENT_RETAINED_OBSERVED' in stdout.getvalue(), not changed)

    def test_tools_fail_quietly_and_invalid_artifacts_do_not_execute(self):
        elf = bytearray(32)
        elf[:6], elf[18:20] = b'\x7fELF\x02\x01', b'\x3e\x00'
        sentinel = 'DEBUGGER_DETAILS_MUST_NOT_APPEAR'
        for data, error in ((b'bad', AssertionError('must not execute')),
                            (elf, subprocess.CalledProcessError(1, [sentinel], output=sentinel)),
                            (elf, subprocess.TimeoutExpired([sentinel], 30, output=sentinel))):
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch('sys.argv', ['probe', '--binary', 'fixture', '--owner', 'cached', '--path', 'public']), \
                 patch.object(Path, 'resolve', return_value=Path('/fixture')), \
                 patch.object(Path, 'read_bytes', return_value=data), \
                 patch.object(R.subprocess, 'run', side_effect=error) as run, \
                 redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(R.main(), 2)
                if data == b'bad': run.assert_not_called()
            self.assertEqual(stdout.getvalue(), '')
            self.assertNotIn(sentinel, stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
