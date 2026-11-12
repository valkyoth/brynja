#!/usr/bin/env python3
"""Synthetic finite-screen verdict and integrity regressions; never measure."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('finite_analysis', Path(__file__).with_name('analyze-aes-dit-finite.py'))
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class FiniteAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / 'data'
        self.data.mkdir()
        self.plan = {'system': 'Darwin', 'machine': 'arm64',
                     'binaries': {c: {'binary': '/retained/' + c, 'probe': '/probe/' + c}
                                  for c in a.worker.COMPILERS}}
        for key, filename in (('collector_sha256', 'collect-aes-dit-finite.py'),
                              ('timing_parser_sha256', 'check-aes-fixed-random.py'),
                              ('controls_parser_sha256', 'aes_timing_controls.py')):
            self.plan[key] = a.worker.digest(a.HERE / filename)
        self.manifest = self.root / 'declaration.json'
        a.worker.write(self.manifest, self.plan)
        self.expected = a.worker.digest(self.manifest)
        a.worker.write(self.data / 'declaration.json', self.plan)
        a.worker.write(self.data / 'complete.json', {'launches': 32})
        a.worker.write(self.data / 'host.json', {'declaration_sha256': self.expected,
                       'environment': a.worker.ENV, 'uname': ['Darwin', 'test', '', '', 'arm64']})
        for c in a.worker.COMPILERS:
            self.record('probe-' + c, ['/probe/' + c], 'AES_DIT_HOST_BUNDLE_PASS\n')
        self.names = []
        for i, (r, c, control) in enumerate(a.worker.launches(), 1):
            name = f'{i:02d}-round{r}-{c}-{control}'
            self.names.append(name)
            self.record(name, ['/retained/' + c, 'measure', control],
                        f'AES_FORCED_AUTHORITY: ArmAes\nAES_TIMING_CONTROL: {control}\nsynthetic')

    def record(self, name, command, text):
        out, err = (self.data / (name + suffix) for suffix in ('.stdout', '.stderr'))
        out.write_text(text)
        err.write_bytes(b'')
        a.worker.write(self.data / (name + '.json'), {'command': command,
                       'returncode': 0, 'error': None, 'stdout_sha256': a.worker.digest(out),
                       'stderr_sha256': a.worker.digest(err)})

    def analyze(self, effects=None):
        with patch.object(a.policy, 'parse', side_effect=effects,
                          return_value=[{'alarm': False, 'inconclusive': False}]) as parse:
            result = a.analyze(self.data, self.manifest, self.expected)
        return result, parse

    def test_every_launch_parsed_no_pooling(self):
        result, parse = self.analyze()
        self.assertEqual(parse.call_count, 32)
        self.assertTrue(result['screen_passed'])
        self.assertEqual(len(result['launches']), 32)

    def test_shared_alarm_or_noise_fails_even_when_other_launches_clean(self):
        for position in (1, 3, 29, 31):
            for flag in ('alarm', 'inconclusive'):
                effects = [[{'alarm': False, 'inconclusive': False}] for _ in range(32)]
                effects[position] = [{**effects[position][0], flag: True}]
                result, parse = self.analyze(effects)
                self.assertFalse(result['screen_passed'])
                self.assertEqual(parse.call_count, 32)

    def test_separate_flags_retained_without_claiming_diagnostic_pass(self):
        effects = [[{'alarm': False, 'inconclusive': False}] for _ in range(32)]
        effects[0] = [{'alarm': True, 'inconclusive': True}]
        result, _ = self.analyze(effects)
        self.assertTrue(result['screen_passed'])
        self.assertEqual(result['launches'][0]['alarms'], 1)
        self.assertEqual(result['launches'][0]['inconclusive'], 1)
        self.assertEqual(result['launches'][0]['role'], 'address-diagnostic-not-pass')

    def test_bad_diagnostic_data_fails_screen_and_keeps_later_launches(self):
        effects = [ValueError('incomplete population')] + [[{'alarm': False, 'inconclusive': False}]] * 31
        result, parse = self.analyze(effects)
        self.assertFalse(result['screen_passed'])
        self.assertIn('validation_error', result['launches'][0])
        self.assertEqual(parse.call_count, 32)

    def test_output_tampering_rejected_before_statistics(self):
        (self.data / (self.names[0] + '.stdout')).write_text('tampered')
        result, parse = self.analyze()
        self.assertFalse(result['screen_passed'])
        self.assertIn('hash mismatch', result['launches'][0]['validation_error'])
        self.assertEqual(parse.call_count, 31)

    def test_wrong_marker_rejected_even_with_matching_output_hash(self):
        path = self.data / (self.names[0] + '.stdout')
        path.write_text('AES_FORCED_AUTHORITY: Wrong\n')
        record = self.data / (self.names[0] + '.json')
        data = json.loads(record.read_text())
        data['stdout_sha256'] = a.worker.digest(path)
        record.write_text(json.dumps(data))
        result, parse = self.analyze()
        self.assertFalse(result['screen_passed'])
        self.assertIn('authority', result['launches'][0]['validation_error'])
        self.assertEqual(parse.call_count, 31)

    def test_missing_completion_rejected(self):
        (self.data / 'complete.json').unlink()
        with self.assertRaises(ValueError):
            self.analyze()

    def test_undeclared_extra_launch_rejected(self):
        (self.data / 'extra.stdout').write_text('cannot select best launch')
        with self.assertRaisesRegex(ValueError, 'extra'):
            self.analyze()


if __name__ == '__main__':
    unittest.main()
