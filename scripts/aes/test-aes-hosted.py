#!/usr/bin/env python3
"""Hosted runner must distinguish nonexecution from accelerated coverage."""
import importlib.util
from pathlib import Path
import unittest
import tomllib

SPEC = importlib.util.spec_from_file_location("hosted", Path(__file__).with_name("check-aes-hosted.py"))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class HostedTests(unittest.TestCase):
    def test_registry_modes_and_source_closure(self):
        root = Path(__file__).resolve().parents[2]
        registry = tomllib.loads((root / 'verification/checks.toml').read_text())
        checks = {c['id']: c for c in registry['checks'] if c.get('category') == 'aes-hosted'}
        self.assertEqual(set(checks), {f'hosted-{mode}-{endpoint}' for mode in ('native', 'arm-qemu')
                                      for endpoint in ('msrv', 'current')})
        for mode in ('native', 'arm-qemu'):
            for endpoint, tc in (('msrv', '1.90.0'), ('current', '1.99.1')):
                check = checks[f'hosted-{mode}-{endpoint}']
                expected = ['python3', 'scripts/aes/check-aes-hosted.py', '--toolchain', tc]
                if mode == 'arm-qemu':
                    expected.append('--qemu-aarch64')
                    self.assertIn('aes-kernel-qemu', check['inputs'])
                self.assertEqual(check['command'], expected)
                self.assertEqual(check['success']['exact_tests'], 6)
                self.assertEqual(check['success']['unique_lines'], [f'AES_HOSTED_PASS: {mode} {tc}'])
                self.assertTrue({'aes-hosted-execution', 'aes-build', 'cpu-source', 'hosted-cpu-source',
                                 'hash-core', 'sha2-source', 'sha3-source', 'hmac-source',
                                 'kmac-source', 'tuplehash-source', 'parallelhash-source'} <= set(check['inputs']))

    def test_route_markers_are_disjoint(self):
        accelerated = "\n".join((*RUNNER.MARKERS, "AES_HOSTED_ACCELERATED_PASS"))
        unavailable = "AES_HOSTED_UNAVAILABLE_PASS"
        RUNNER.validate(accelerated, True)
        RUNNER.validate(unavailable, False)
        for output, expected in ((accelerated, False), (unavailable, True),
                                 (accelerated + "\n" + unavailable, True), ("", True), ("", False)):
            with self.assertRaises(ValueError):
                RUNNER.validate(output, expected)

    def test_every_corpus_marker_is_required_once(self):
        text = "\n".join((*RUNNER.MARKERS, "AES_HOSTED_ACCELERATED_PASS"))
        for marker in (*RUNNER.MARKERS, "AES_HOSTED_ACCELERATED_PASS"):
            for output in (text.replace(marker, ""), text + "\n" + marker,
                           text.replace(marker, "not executed " + marker)):
                with self.assertRaises(ValueError):
                    RUNNER.validate(output, True)


if __name__ == "__main__":
    unittest.main()
