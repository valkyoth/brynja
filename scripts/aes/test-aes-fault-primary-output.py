#!/usr/bin/env python3
"""Primary-result runner regression contracts; mock transcripts are not evidence."""
from contextlib import redirect_stdout, redirect_stderr
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'primary_probe', Path(__file__).with_name('check-aes-fault-primary-output.py'))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def transcript(width, path, owner, case):
    prefix = 'BRYNJA_' + owner.upper()
    markers = ['PRIMARY_ENTRY 1']
    if case != 'baseline':
        markers += ['PRIMARY_MUTATED 1']
    markers += ['PRIMARY_RETURN 1']
    if case == 'combined':
        markers += ['PRIMARY_FORGED 1']
    return '\n'.join([
        P.R.C.identity(width, path, 'baseline', owner),
        'Hardware assisted breakpoint 1 at 0x1', 'Hardware assisted breakpoint 2 at 0x1',
        'hit Breakpoint 1, 0x1', 'hit Breakpoint 2, 0x1', *markers,
        prefix+'_EVIDENCE_CFG=false', f'{prefix}_CASE={width}:{path}',
        prefix+'_STORAGE_CLEARED', prefix+('_ACCEPTED' if case == 'baseline' else '_REJECTED_RETIRED'),
        'test result: ok. 1 passed; 0 failed; 0 ignored;', 'exited normally'])


class PrimaryOutputRunner(unittest.TestCase):
    def test_all_positions_require_exact_events_and_outcomes(self):
        for width in P.R.C.ANSWERS:
            for path in P.R.C.PATHS:
                for owner in P.R.C.OWNERS:
                    for case in P.CASES:
                        good = transcript(width, path, owner, case)
                        for byte in range(16):
                            P.validate(good, width, path, owner, case, byte)
                        for marker in good.splitlines():
                            if marker.startswith(('PRIMARY_', 'BRYNJA_')):
                                for replacement in ('', marker+'\n'+marker):
                                    with self.assertRaises(ValueError):
                                        P.validate(good.replace(marker, replacement), width, path, owner, case, 0)
                            if marker.startswith('PRIMARY_'):
                                with self.assertRaises(ValueError):
                                    P.validate(good.replace(marker, marker.replace(' 1', ' 0')), width, path, owner, case, 0)

    def test_wrong_execution_or_accepted_fault_never_passes(self):
        good = transcript(16, 'public', 'cached', 'combined')
        for old, new in [('EVIDENCE_CFG=false', 'EVIDENCE_CFG=true'),
                         ('hit Breakpoint', 'missed Breakpoint'),
                         ('Hardware assisted breakpoint', 'Breakpoint'),
                         ('test result: ok.', 'test result: FAILED.'),
                         ('exited normally', 'exited abnormally'),
                         ('_REJECTED_RETIRED', '_ACCEPTED')]:
            with self.assertRaises(ValueError):
                P.validate(good.replace(old, new), 16, 'public', 'cached', 'combined', 0)
        for path in ('encrypt', 'decrypt'):
            with self.assertRaises(ValueError):
                P.validate(good, 16, path, 'cached', 'combined', 0)

    def test_commands_mutate_only_primary_and_confirm_failed_return(self):
        for case in P.CASES:
            for byte in range(16):
                cmds, _ = P.commands(16, 'public', 'cached', case, byte, dict(symbol=P.P.COPY, ret=100))
                writes = [command for command in cmds if command.startswith('set *')]
                self.assertEqual(writes, [] if case == 'baseline' else
                                 [f'set *($primary+{byte}) = *($primary+{byte}) ^ 1'])
                self.assertEqual('set $al=0' in cmds, case == 'combined')
                self.assertEqual(sum(command.startswith('hbreak ') for command in cmds), 2)
                self.assertIn('set print thread-events off', cmds)
                if case == 'combined':
                    check = next(command for command in cmds if 'PRIMARY_RETURN' in command)
                    self.assertIn('$al == 1', check)
                    self.assertIn('$before0', check)
                    self.assertLess(cmds.index(check), cmds.index('set $al=0'))

    def test_invalid_selection_rejected_before_debugging(self):
        for width, path, owner, case, byte in [(17,'public','cached','baseline',0),
                (16,'unknown','cached','baseline',0), (16,'public','unknown','baseline',0),
                (16,'public','cached','unknown',0), (16,'public','cached','combined',-1),
                (16,'public','cached','combined',16)]:
            with self.assertRaises(ValueError):
                P.commands(width, path, owner, case, byte, dict(symbol=P.P.COPY, ret=100))
            with self.assertRaises(ValueError):
                P.validate('', width, path, owner, case, byte)

    def test_invalid_artifact_is_quiet_and_never_executed(self):
        output, errors = io.StringIO(), io.StringIO()
        with patch('sys.argv', ['probe','--binary','fixture','--owner','cached','--path','public']), \
             patch.object(Path, 'resolve', return_value=Path('/fixture')), \
             patch.object(Path, 'read_bytes', return_value=b'invalid'), \
             patch.object(P.subprocess, 'run', side_effect=AssertionError('must not execute')), \
             redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(P.main(), 2)
        self.assertNotIn('DEVELOPMENT_PRIMARY_OUTPUT_OBSERVED', output.getvalue())
        self.assertNotIn('PRIMARY_ENTRY', errors.getvalue())


if __name__ == '__main__':
    unittest.main()
