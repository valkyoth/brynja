#!/usr/bin/env python3
"""Completion runner contract tests; mock output is not native evidence."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    'completion_probe', Path(__file__).with_name('check-aes-fault-completion.py'))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def transcript(width, path, owner, case):
    prefix = 'BRYNJA_' + owner.upper()
    markers = ['COMPLETION_ENTRY 1', 'COMPLETION_CAPTURE 1',
               'COMPLETION_FIRST 1']
    if case.startswith('input-'):
        markers.append('COMPLETION_MUTATED 1')
    markers += ['COMPLETION_SECOND 1', 'COMPLETION_RETURN 1']
    if case == 'input-plus-completion-bypass':
        markers.append('COMPLETION_FORGED 1')
    if case == 'completion-bit':
        markers.append('COMPLETION_BIT 1')
    return '\n'.join([
        P.R.C.identity(width, path, 'baseline', owner),
        prefix + '_EVIDENCE_CFG=false', f'{prefix}_CASE={width}:{path}',
        *[f'Hardware assisted breakpoint {n} at 0x1' for n in range(1, 5)],
        *[f'hit Breakpoint {n}, 0x1' for n in range(1, 6)],
        *markers, prefix + '_STORAGE_CLEARED',
        prefix + ('_ACCEPTED' if case == 'baseline' else '_REJECTED_RETIRED'),
        'test result: ok. 1 passed; 0 failed; 0 ignored;',
        'exited normally',
    ])


class CompletionRunner(unittest.TestCase):
    def test_exact_matrix_events_and_terminal_outcomes(self):
        for width in P.R.C.ANSWERS:
            for path in P.R.C.PATHS:
                for owner in P.R.C.OWNERS:
                    for case in P.CASES:
                        good = transcript(width, path, owner, case)
                        P.validate(good, width, path, owner, case)
                        for marker in ('COMPLETION_RETURN 1',
                                       'BRYNJA_' + owner.upper() + '_STORAGE_CLEARED'):
                            with self.assertRaises(ValueError):
                                P.validate(good.replace(marker, marker[:-1] + '0'),
                                           width, path, owner, case)
                        wrong = good.replace('_ACCEPTED', '_REJECTED_RETIRED') if case == 'baseline' \
                            else good.replace('_REJECTED_RETIRED', '_ACCEPTED')
                        with self.assertRaises(ValueError):
                            P.validate(wrong, width, path, owner, case)
                        with self.assertRaises(ValueError):
                            P.validate(good.replace('EVIDENCE_CFG=false', 'EVIDENCE_CFG=true'),
                                       width, path, owner, case)
                        with self.assertRaises(ValueError):
                            P.validate(good.replace('hit Breakpoint', 'missed Breakpoint'),
                                       width, path, owner, case)

    def test_bypass_targets_result_after_independent_capture(self):
        for case in P.CASES:
            commands, test = P.commands(16, 'public', 'cached', case,
                                        dict(symbol=P.COMPUTE, ret=123), P.R.CAPTURE,
                                        dict(symbol=P.R.COPY, ret=456))
            self.assertEqual(test, P.R.C.identity(16, 'public', 'baseline', 'cached'))
            self.assertEqual(sum(command.startswith('hbreak ') for command in commands), 4)
            self.assertEqual('set *$first = *$first ^ 1' in commands,
                             case.startswith('input-'))
            self.assertEqual('set $al = 0' in commands,
                             case == 'input-plus-completion-bypass')
            self.assertEqual('set *$completion = *$completion ^ 1' in commands,
                             case == 'completion-bit')
            self.assertLess(commands.index('disable 3'), commands.index('enable 3'))
            self.assertLess(commands.index('enable 3'), len(commands) - 1 - commands[::-1].index('disable 3'))
            self.assertLess(commands.index('disable 4'), commands.index('enable 4'))
            self.assertLess(commands.index('enable 4'), len(commands) - 1 - commands[::-1].index('disable 4'))

    def test_invalid_case_and_missing_markers_reject(self):
        with self.assertRaises(ValueError):
            P.commands(16, 'public', 'cached', 'unknown', {}, '', {})
        for case in P.CASES:
            with self.assertRaises(ValueError):
                P.validate('', 16, 'public', 'cached', case)

    def test_diagnostic_reports_only_confirmation_booleans(self):
        good = transcript(16, 'public', 'cached', 'baseline')
        test = P.R.C.identity(16, 'public', 'baseline', 'cached')
        self.assertEqual(set(P.confirmation_flags(good, test)),
                         {'breakpoints_declared', 'breakpoints_hit', 'fixture_identity',
                          'fixture_passed', 'normal_exit'})
        self.assertTrue(all(P.confirmation_flags(good, test).values()))
        self.assertFalse(P.confirmation_flags(good.replace('exited normally', ''),
                                              test)['normal_exit'])


if __name__ == '__main__':
    unittest.main()
