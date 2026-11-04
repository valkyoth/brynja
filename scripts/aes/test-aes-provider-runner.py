#!/usr/bin/env python3
"""Provider compiler-runner regression controls; no device/cryptographic claims."""
from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('provider_api', Path(__file__).with_name('check-aes-provider-api.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ProviderRunnerTests(unittest.TestCase):
    def test_exact_probe_population_and_distinct_controls(self):
        cases = runner.probes()
        self.assertEqual(len(cases), 25)
        self.assertEqual(len({row[0] for row in cases}), 25)
        for name, negative, positive, code in cases:
            self.assertNotEqual(negative, positive, name)
            self.assertRegex(code, '^E[0-9]{4}$')

    def test_both_routes_and_independent_feature_sets(self):
        with patch.object(runner.api, 'run_probes') as run, redirect_stdout(io.StringIO()) as output:
            runner.run('1.90.0')
        self.assertEqual(run.call_count, 8)
        self.assertEqual(sum(len(call.kwargs['cases']) for call in run.call_args_list), 56)
        for call in run.call_args_list:
            self.assertEqual(call.args[0], '1.90.0')
            self.assertEqual(call.args[2]['CARGO_NET_OFFLINE'], 'true')
            self.assertEqual(call.args[2]['RUSTUP_AUTO_INSTALL'], '0')
            for _, negative, positive, _ in call.kwargs['cases']:
                if call.kwargs['package'] == 'brynja':
                    self.assertNotIn('brynja_crypto', negative + positive)
                    self.assertIn('brynja::crypto', negative + positive)
        self.assertEqual({call.kwargs['features'] for call in run.call_args_list},
                         {'', 'external-key-provider', 'hazmat-aes-block',
                          'hazmat-aes-block,external-key-provider'})
        self.assertIn('56 paired probes; direct and facade; independent opt-ins', output.getvalue())

    def test_any_probe_failure_prevents_completion_marker(self):
        with patch.object(runner.api, 'run_probes', side_effect=ValueError('wrong diagnostic')), \
             redirect_stdout(io.StringIO()) as output:
            with self.assertRaisesRegex(ValueError, 'wrong diagnostic'):
                runner.run('1.99.1')
        self.assertNotIn('AES_PROVIDER_API_PASS', output.getvalue())


if __name__ == '__main__':
    unittest.main()
