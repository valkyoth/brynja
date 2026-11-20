#!/usr/bin/env python3
"""Cached native runner regressions; synthetic transcripts are not fault evidence."""
from contextlib import redirect_stdout, redirect_stderr
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'cached_probe', Path(__file__).with_name('check-aes-fault-cached.py'))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


def transcript(width, path, case, owner='cached'):
    markers = ['CACHED_SITE 1']
    if case == 'state-after-restore':
        markers += ['CACHED_RESTORED 1']
    if case != 'baseline':
        markers += ['CACHED_MUTATED 1']
    if case in ('report-forged', 'result-forged'):
        markers += ['CACHED_DENIED 1', 'CACHED_FORGED 1']
    stops = 2 if case in C.P.CASES else 1
    prefix = 'BRYNJA_'+owner.upper()
    return '\n'.join([
        C.identity(width, path, case, owner),
        prefix+'_EVIDENCE_CFG=false', f'{prefix}_CASE={width}:{path}',
        *[f'Hardware assisted breakpoint {n+1} at 0x1' for n in range(stops)],
        *[f'hit Breakpoint {n+1}, 0x1' for n in range(stops)],
        *markers, prefix+'_STORAGE_CLEARED',
        prefix+('_ACCEPTED' if case == 'baseline' else '_REJECTED_RETIRED'),
        'test result: ok. 1 passed; 0 failed; 0 ignored;', 'exited normally',
    ])


class CachedRunner(unittest.TestCase):
    def test_ephemeral_identity_cannot_reuse_cached_results(self):
        permit = dict(symbol=C.P.PERMIT, ret=123)
        for width in C.ANSWERS:
            for path in C.PATHS:
                for case in C.CASES:
                    cached = transcript(width, path, case)
                    ephemeral = cached.replace('BRYNJA_CACHED_', 'BRYNJA_EPHEMERAL_').replace('native_cached_', 'native_ephemeral_')
                    C.validate(ephemeral, width, path, case, 'ephemeral')
                    with self.assertRaises(ValueError):
                        C.validate(cached, width, path, case, 'ephemeral')
                    with self.assertRaises(ValueError):
                        C.validate(ephemeral, width, path, case, 'cached')
                    commands, test = C.commands(width, path, case, permit, 'guard', list(range(31)), 'ephemeral')
                    self.assertEqual(test, C.identity(width, path, case, 'ephemeral'))
                    self.assertEqual(commands, C.commands(width, path, case, permit, 'guard', list(range(31)), 'cached')[0])
        with self.assertRaises(ValueError):
            C.identity(16, 'public', 'baseline', 'unknown')

    def test_every_case_requires_exact_ordered_checkpoints(self):
        for width in C.ANSWERS:
            for path in C.PATHS:
                for case in C.CASES:
                    good = transcript(width, path, case)
                    C.validate(good, width, path, case)
                    C.validate(good.replace('\n', '\r\n'), width, path, case)
                    for line in good.splitlines():
                        if line.startswith(('CACHED_', 'BRYNJA_')):
                            for bad in ('missing', line+' extra', line+'\n'+line):
                                with self.assertRaises(ValueError):
                                    C.validate(good.replace(line, bad, 1), width, path, case)
                        if line.startswith('CACHED_'):
                            with self.assertRaises(ValueError):
                                C.validate(good.replace(line, line[:-1]+'0'), width, path, case)
                    for old, new in (
                        ('EVIDENCE_CFG=false', 'EVIDENCE_CFG=true'),
                        ('Hardware assisted breakpoint', 'Breakpoint'),
                        ('hit Breakpoint', 'missed Breakpoint'),
                        ('test result: ok.', 'test result: FAILED.'),
                        ('exited normally', 'exited abnormally'),
                    ):
                        with self.assertRaises(ValueError):
                            C.validate(good.replace(old, new), width, path, case)

    def test_width_path_or_outcome_substitution_is_rejected(self):
        for width in C.ANSWERS:
            for path in C.PATHS:
                for case in C.CASES:
                    text = transcript(width, path, case)
                    for other in C.PATHS:
                        if other != path:
                            with self.assertRaises(ValueError):
                                C.validate(text, width, other, case)
                    for other in C.ANSWERS:
                        if other != width:
                            with self.assertRaises(ValueError):
                                C.validate(text, other, path, case)
                    a, b = 'BRYNJA_CACHED_ACCEPTED', 'BRYNJA_CACHED_REJECTED_RETIRED'
                    wrong = text.replace(a, b) if case == 'baseline' else text.replace(b, a)
                    with self.assertRaises(ValueError):
                        C.validate(wrong, width, path, case)

    def test_command_sites_are_scoped_to_the_final_permit(self):
        permit = dict(symbol=C.P.PERMIT, ret=123)
        for width in C.ANSWERS:
            for path in C.PATHS:
                for case in C.CASES:
                    commands, test = C.commands(width, path, case, permit, 'guard', list(range(31)))
                    self.assertEqual(test, C.identity(width, path, case))
                    self.assertIn(f"hbreak *'{C.P.PERMIT}'", commands)
                    self.assertFalse(any(c.startswith(('break ', 'ignore ')) for c in commands))
                    self.assertEqual(sum(c.startswith('hbreak ') for c in commands),
                                     2 if case in C.P.CASES else 1)
                    self.assertIn('set $owner=(unsigned char*)$r8', commands)
                    if case in C.P.CASES:
                        self.assertLess(commands.index('disable 1'), commands.index('enable 2'))
                    if case == 'baseline':
                        self.assertFalse(any(c.startswith(('set *', 'set $al')) for c in commands))
                    for target in ('primary', 'secondary'):
                        self.assertEqual(f'set *${target} = *${target} ^ 1' in commands, case == target)
                    self.assertEqual('set $al = $al ^ 1' in commands, case == 'result-forged')

    def test_invalid_experiment_and_answer_are_rejected(self):
        for args in ((15, 'public', 'baseline'), (16, 'bad', 'baseline'), (16, 'public', 'bad')):
            with self.assertRaises(ValueError):
                C.identity(*args)
            with self.assertRaises(ValueError):
                C.validate('', *args)
        for value in ('', '00', 'z'*32):
            with self.assertRaises(ValueError):
                C.answer_at('$p', value)

    def test_main_requires_all_cases_and_unchanged_artifact(self):
        elf = bytearray(32)
        elf[:6], elf[18:20] = b'\x7fELF\x02\x01', b'\x3e\x00'
        for changed in (False, True):
            for path, owner in [(p, o) for p in C.PATHS for o in C.OWNERS]:
                runs = [subprocess.CompletedProcess(['objdump'], 0, 'dump', '')]
                runs += [subprocess.CompletedProcess(['gdb'], 0, transcript(w, path, c, owner), '')
                         for w in C.ANSWERS for c in C.CASES]
                stdout = io.StringIO()
                with patch('sys.argv', ['probe', '--binary', 'fixture', '--path', path, '--owner', owner]), \
                     patch.object(Path, 'resolve', return_value=Path('/fixture')), \
                     patch.object(Path, 'read_bytes', side_effect=[elf, elf+b'x' if changed else elf]), \
                     patch.object(C.subprocess, 'run', side_effect=runs) as run, \
                     patch.object(C.P.TX.GUARD, 'inspect', return_value=('guard', list(range(31)))), \
                     patch.object(C.P.TX, 'body', return_value=dict(symbol=C.P.PERMIT, ret=123)), \
                     redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                    self.assertEqual(C.main(), 2 if changed else 0)
                    self.assertEqual(run.call_count, 22)
                self.assertEqual(f'DEVELOPMENT_{owner.upper()}_OBSERVED' in stdout.getvalue(), not changed)

    def test_tool_failure_is_quiet_and_never_passes(self):
        elf = bytearray(32)
        elf[:6], elf[18:20] = b'\x7fELF\x02\x01', b'\x3e\x00'
        sentinel = 'DEBUGGER_DETAILS_MUST_NOT_APPEAR'
        for error in (subprocess.CalledProcessError(1, [sentinel], output=sentinel),
                      subprocess.TimeoutExpired([sentinel], 30, output=sentinel),
                      OSError(sentinel)):
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch('sys.argv', ['probe', '--binary', 'fixture', '--path', 'public']), \
                 patch.object(Path, 'resolve', return_value=Path('/fixture')), \
                 patch.object(Path, 'read_bytes', return_value=elf), \
                 patch.object(C.subprocess, 'run', side_effect=error), \
                 redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(C.main(), 2)
            self.assertEqual(stdout.getvalue(), '')
            self.assertNotIn(sentinel, stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
