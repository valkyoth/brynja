#!/usr/bin/env python3
"""Native round-skip runner contracts; mock transcripts are not evidence."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    'round_probe', Path(__file__).with_name('check-aes-fault-round-skip.py'))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def transcript(width, path, owner, step, bypass=False):
    prefix = 'BRYNJA_' + owner.upper()
    markers = ['ROUND_ENTRY 1']
    if step:
        markers += ['ROUND_TARGET 1', 'ROUND_SKIPPED 1']
    if bypass:
        markers += ['ROUND_COPY_ENTRY 1', 'ROUND_COPY_FAILED 1', 'ROUND_COPY_FORGED 1']
    return '\n'.join([
        P.R.C.identity(width, path, 'baseline', owner),
        prefix + '_EVIDENCE_CFG=false', f'{prefix}_CASE={width}:{path}',
        'Hardware assisted breakpoint 1 at 0x1',
        'Hardware assisted breakpoint 2 at 0x1',
        *(['Hardware assisted breakpoint 3 at 0x1', 'Hardware assisted breakpoint 4 at 0x1'] if bypass else []),
        'hit Breakpoint 1, 0x1',
        *(['hit Breakpoint 2, 0x1'] if step else []),
        *(['hit Breakpoint 3, 0x1', 'hit Breakpoint 4, 0x1'] if bypass else []),
        *markers, prefix + '_STORAGE_CLEARED',
        prefix + ('_REJECTED_RETIRED' if step else '_ACCEPTED'),
        'test result: ok. 1 passed; 0 failed; 0 ignored;',
        'exited normally',
    ])


class RoundSkipRunner(unittest.TestCase):
    def test_combined_skip_and_guarded_write_bypass_requires_every_event(self):
        for width in P.R.C.ANSWERS:
            for path in P.R.C.PATHS:
                for owner in P.R.C.OWNERS:
                    for step in range(1, width // 4 + 7):
                        good = transcript(width, path, owner, step, True)
                        P.validate(good, width, path, owner, step, True)
                        for marker in ('ROUND_COPY_ENTRY 1', 'ROUND_COPY_FAILED 1', 'ROUND_COPY_FORGED 1'):
                            for replacement in ('', marker.replace(' 1', ' 0'), marker+'\n'+marker):
                                with self.assertRaises(ValueError):
                                    P.validate(good.replace(marker, replacement), width, path, owner, step, True)
                        with self.assertRaises(ValueError):
                            P.validate(good.replace('_REJECTED_RETIRED', '_ACCEPTED'), width, path, owner, step, True)
                        with self.assertRaises(ValueError):
                            P.validate(good, width, path, owner, step, False)
                        with self.assertRaises(ValueError):
                            P.validate(transcript(width, path, owner, step), width, path, owner, step, True)

    def test_combined_commands_target_write_return_and_require_real_skip(self):
        transform = dict(symbol=P.TRANSFORM, ret=123)
        copy = dict(symbol=P.COPY, ret=456)
        commands, _ = P.commands(16, 'public', 'cached', 1, transform, P.SUBSTITUTE, copy)
        self.assertEqual(sum(c.startswith('hbreak ') for c in commands), 4)
        self.assertIn("hbreak *('"+P.COPY+"'+456)", commands)
        self.assertEqual(commands.count('set $al=0'), 2)
        self.assertLess(commands.index('disable 2'), commands.index('enable 3'))
        self.assertTrue(any('$al == 1' in c and '$before0' in c for c in commands))
        with self.assertRaises(ValueError):
            P.commands(16, 'public', 'cached', 0, transform, P.SUBSTITUTE, copy)
        with self.assertRaises(ValueError):
            P.validate('', 16, 'public', 'cached', 0, True)

    def test_exact_identity_and_outcome_for_all_rounds(self):
        for width in P.R.C.ANSWERS:
            for path in P.R.C.PATHS:
                for owner in P.R.C.OWNERS:
                    for step in range(width // 4 + 7):
                        good = transcript(width, path, owner, step)
                        P.validate(good, width, path, owner, step)
                        for old, new in (
                            ('ROUND_ENTRY 1', 'ROUND_ENTRY 0'),
                            ('EVIDENCE_CFG=false', 'EVIDENCE_CFG=true'),
                            ('hit Breakpoint', 'missed Breakpoint'),
                            ('test result: ok.', 'test result: FAILED.'),
                            ('exited normally', 'exited abnormally'),
                            ('_REJECTED_RETIRED', '_ACCEPTED') if step else
                            ('_ACCEPTED', '_REJECTED_RETIRED'),
                        ):
                            with self.assertRaises(ValueError):
                                P.validate(good.replace(old, new), width, path, owner, step)

    def test_skip_targets_selected_substitution_call(self):
        transform = dict(symbol=P.TRANSFORM, ret=123)
        for step in (0, 1, 3, 10):
            commands, test = P.commands(16, 'public', 'cached', step,
                                        transform, P.SUBSTITUTE)
            self.assertEqual(test, P.R.C.identity(16, 'public', 'baseline', 'cached'))
            self.assertEqual(sum(c.startswith('hbreak ') for c in commands), 2)
            self.assertEqual('set $rip=$retpc' in commands, step > 0)
            self.assertEqual('set $al=0' in commands, step > 0)
            self.assertEqual('set $transform_start=$pc' in commands, True)
            self.assertEqual(f'ignore 2 {step-1}' in commands, step > 1)
            if step:
                self.assertLess(commands.index('set $retpc=*(unsigned long long*)$rsp'),
                                commands.index('set $rip=$retpc'))

    def test_invalid_steps_reject_before_debugging(self):
        for step in (-1, 11):
            with self.assertRaises(ValueError):
                P.commands(16, 'public', 'cached', step,
                           dict(symbol=P.TRANSFORM, ret=123), P.SUBSTITUTE)
            with self.assertRaises(ValueError):
                P.validate('', 16, 'public', 'cached', step)


if __name__ == '__main__':
    unittest.main()
