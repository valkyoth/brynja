#!/usr/bin/env python3
"""Exact paired-probe population and fail-closed compiler diagnostic checks."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

SPEC = importlib.util.spec_from_file_location('execution_api', Path(__file__).with_name('check-aes-execution-api.py'))
API = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(API)


class ExecutionApiTests(unittest.TestCase):
    def result(self, count=3, code='E0277', primary=True, filename='probe.rs', status=1):
        error = {'$message_type': 'diagnostic', 'level': 'error', 'code': {'code': code},
                 'spans': [{'is_primary': primary, 'file_name': filename}]}
        return SimpleNamespace(returncode=status, stderr='\n'.join(json.dumps(error) for _ in range(count)))

    def test_exact_multiple_diagnostics(self):
        self.assertTrue(API.diagnostic_matches(self.result(), ('E0277', 3), Path('probe.rs')))
        for count in (0, 1, 2, 4):
            self.assertFalse(API.diagnostic_matches(self.result(count), ('E0277', 3), Path('probe.rs')))

    def test_wrong_code_location_status_or_malformed_output_rejected(self):
        for result in (self.result(code='E0432'), self.result(primary=False),
                       self.result(filename='dependency.rs'), self.result(status=0),
                       self.result(status=101), SimpleNamespace(returncode=1, stderr='not JSON')):
            self.assertFalse(API.diagnostic_matches(result, ('E0277', 3), Path('probe.rs')))

    def test_single_error_remains_exact(self):
        self.assertTrue(API.diagnostic_matches(self.result(1), 'E0277', Path('probe.rs')))
        self.assertFalse(API.diagnostic_matches(self.result(3), 'E0277', Path('probe.rs')))

    def test_all_owners_and_authority_probes_present(self):
        cases = API.probes()
        self.assertEqual(len(cases), 106)
        self.assertEqual(len({name for name, *_ in cases}), 106)
        for bits in (128, 192, 256):
            self.assertEqual({name for name, *_ in cases if name.startswith(f'expansion-{bits}-')},
                             {f'expansion-{bits}-{kind}' for kind in ('key-width', 'schedule-width', 'alias')})
            for suffix in ('Key', 'ExpandedKey'):
                self.assertEqual(sum(name.startswith(f'Aes{bits}{suffix}-') for name, *_ in cases), 15)

    def test_width_probes_are_paired_for_every_owner_and_operation(self):
        cases = {name: (negative, positive, code) for name, negative, positive, code in API.probes()}
        for bits, key_bytes, schedule_bytes in ((128, 16, 176), (192, 24, 208), (256, 32, 240)):
            for suffix, storage in (('Key', key_bytes), ('ExpandedKey', schedule_bytes)):
                owner = f'Aes{bits}{suffix}'
                mutations = [('key-width', f'&[0;{key_bytes}]', f'&[0;{key_bytes-1}]'),
                             ('storage-width', f'mut s=[0;{storage}]', f'mut s=[0;{storage+1}]')]
                for method in ('encrypt_block', 'decrypt_block', 'encrypt_block_public'):
                    mutations.extend([(method + '-input-width', f'.{method}(&[0;16]', f'.{method}(&[0;15]'),
                                      (method + '-output-width', '&mut[0;16]', '&mut[0;17]')])
                for name, valid, invalid in mutations:
                    negative, positive, code = cases[owner + '-' + name]
                    self.assertEqual(code, 'E0308')
                    self.assertNotEqual(positive, negative)
                    self.assertEqual(negative, positive.replace(valid, invalid))
                    self.assertIn(owner + '::new(', positive)


if __name__ == '__main__':
    unittest.main()
