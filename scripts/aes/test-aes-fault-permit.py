#!/usr/bin/env python3
"""Regression tests for permit runner structure; not native fault evidence."""
import importlib.util
from contextlib import redirect_stdout, redirect_stderr
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'permit_probe', Path(__file__).with_name('check-aes-fault-permit.py')
)
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


class PermitRunner(unittest.TestCase):
    def test_commands_use_hardware_stops_and_mutate_only_declared_site(self):
        root = dict(symbol=P.TX.ROOT, ret=100)
        permit = dict(symbol=P.PERMIT, ret=120)
        offsets = list(range(31))
        for path in ('public', 'secret'):
            for case in P.CASES:
                commands, test = P.commands(case, path, root, permit, P.TX.GUARD.SYMBOL, offsets)
                self.assertTrue(all(not command.startswith('break ') for command in commands))
                self.assertEqual(sum(command.startswith('hbreak ') for command in commands), 3)
                self.assertEqual(commands[6], f"hbreak *'{P.PERMIT}'")
                self.assertFalse(any(command.startswith('ignore ') for command in commands))
                # Inject only after reaching the fresh permit, not at an earlier
                # readback which would reject before the intended experiment.
                self.assertLess(commands.index('disable 2'), commands.index('enable 3'))
                self.assertNotIn(f"hbreak *'{P.TX.CHECK}'", commands)
                self.assertEqual(test, P.TX.TEST if path == 'public' else P.TX.SECRET_TEST)
                self.assertEqual(any('set $al = $al ^ 1' == command for command in commands), case == 'result-forged')
                self.assertEqual(any('set *(unsigned char*)$r8 = 0xa5' == command for command in commands), case == 'report-forged')
                self.assertEqual(any('set *$owner = *$owner ^ 1' == command for command in commands), case == 'state-after-restore')
        with self.assertRaises(ValueError):
            P.commands('unknown', 'public', root, permit, P.TX.GUARD.SYMBOL, offsets)

    def test_validation_requires_each_checkpoint_and_rejection(self):
        for path in ('public', 'secret'):
            for case in P.CASES:
                markers = ['PERMIT_ENTRY 1', 'PERMIT_ACTUAL 1', 'PERMIT_MUTATED 1']
                markers += (['PERMIT_RESTORED 1'] if case == 'state-after-restore'
                            else ['PERMIT_DENIED 1', 'PERMIT_FORGED 1'])
                test = P.TX.TEST if path == 'public' else P.TX.SECRET_TEST
                outcome = ('BRYNJA_TRANSACTION_REJECTED_RESTORED_RETIRED' if path == 'public'
                           else 'BRYNJA_SECRET_REJECTED_CLEARED_RETIRED')
                text = '\n'.join(markers + [
                    test, 'BRYNJA_TRANSACTION_EVIDENCE_CFG=false', outcome,
                    'Hardware assisted breakpoint 1 at 0x1',
                    'Hardware assisted breakpoint 2 at 0x2',
                    'Hardware assisted breakpoint 3 at 0x3',
                    'hit Breakpoint 1, 0x1', 'hit Breakpoint 2, 0x2',
                    'hit Breakpoint 3, 0x3',
                    'test result: ok. 1 passed; 0 failed; 0 ignored;', 'exited normally',
                ])
                P.validate(text, case, path)
                for marker in markers + [outcome, 'exited normally']:
                    with self.assertRaises(ValueError):
                        P.validate(text.replace(marker, 'missing', 1), case, path)
                for marker in markers:
                    for bad in (marker[:-1]+'0', marker+'0', marker+' extra',
                                marker+'\n'+marker, marker+'\n'+marker[:-1]+'0'):
                        with self.assertRaises(ValueError):
                            P.validate(text.replace(marker, bad, 1), case, path)
                forbidden = ('PERMIT_DENIED 1' if case == 'state-after-restore'
                             else 'PERMIT_RESTORED 1')
                with self.assertRaises(ValueError):
                    P.validate(text+'\n'+forbidden, case, path)
                for extra in (outcome, 'BRYNJA_TRANSACTION_ACCEPTED',
                              'BRYNJA_SECRET_ACCEPTED_CLEARED',
                              'BRYNJA_TRANSACTION_EVIDENCE_CFG=true'):
                    with self.assertRaises(ValueError):
                        P.validate(text+'\n'+extra, case, path)
                for old, new in (
                    ('EVIDENCE_CFG=false', 'EVIDENCE_CFG=true'),
                    ('Hardware assisted breakpoint', 'Breakpoint'),
                    ('hit Breakpoint', 'missed Breakpoint'),
                ):
                    with self.assertRaises(ValueError):
                        P.validate(text.replace(old, new), case, path)
                with self.assertRaises(ValueError):
                    P.validate(text, case, 'secret' if path == 'public' else 'public')
                P.validate(text.replace('\n', '\r\n'), case, path)

    def test_invalid_experiments_are_rejected(self):
        for case, path in (('unknown', 'public'), ('report-forged', 'unknown')):
            with self.assertRaises(ValueError):
                P.validate('', case, path)

    def test_tool_failure_does_not_print_commands_or_debugger_output(self):
        elf = bytearray(32)
        elf[:6] = b'\x7fELF\x02\x01'
        elf[18:20] = b'\x3e\x00'
        sentinel = 'PRIVATE_DEBUGGER_TRANSCRIPT_MUST_NOT_APPEAR'
        for error in (
            subprocess.CalledProcessError(1, ['tool', sentinel], output=sentinel),
            subprocess.TimeoutExpired(['tool', sentinel], 30, output=sentinel),
            OSError(sentinel),
        ):
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch('sys.argv', ['probe', '--binary', 'fixture', '--path', 'public']), \
                 patch.object(Path, 'resolve', return_value=Path('/fixture')), \
                 patch.object(Path, 'read_bytes', return_value=elf), \
                 patch.object(P.subprocess, 'run', side_effect=error), \
                 redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(P.main(), 2)
            self.assertEqual(stdout.getvalue(), '')
            self.assertNotIn(sentinel, stderr.getvalue())
            self.assertIn(type(error).__name__, stderr.getvalue())

    def test_invalid_artifact_rejected_before_tools_run(self):
        with patch('sys.argv', ['probe', '--binary', 'fixture', '--path', 'secret']), \
             patch.object(Path, 'resolve', return_value=Path('/fixture')), \
             patch.object(Path, 'read_bytes', return_value=b'not an ELF'), \
             patch.object(P.subprocess, 'run') as run, \
             redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()):
            self.assertEqual(P.main(), 2)
            run.assert_not_called()
            self.assertEqual(stdout.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
