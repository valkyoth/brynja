#!/usr/bin/env python3
"""Native capture rejection tests; fake observations never admit a backend."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('capture', Path(__file__).with_name('capture-sha1-cpu-native.py'))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)

class CaptureTests(unittest.TestCase):
    def test_host_features_and_vendor(self):
        with patch.object(capture.platform,'machine',return_value='x86_64'):
            for text in ('', 'GenuineIntel\nflags: sse2 sha_ni', 'AuthenticAMD\nflags: sse2',
                         'AuthenticAMD\nflags: sse2 sha_ni\nflags: sse2'):
                with patch.object(Path,'read_text',return_value=text), self.assertRaises(ValueError):
                    capture.host('amd-x86_64')
            with patch.object(Path,'read_text',return_value='AuthenticAMD\nflags: sse2 sha_ni'):
                self.assertEqual(capture.host('amd-x86_64'),('AuthenticAMD','+sse2,+sha'))
            with self.assertRaises(ValueError): capture.host('apple-m2-aarch64')

    def test_apple_feature_and_model_rejections(self):
        with patch.object(capture.platform,'machine',return_value='arm64'):
            for values in (['Apple M1'], ['Apple M2','0'], ['Apple M2','1','0'], ['Apple M2','1','1','0']):
                with patch.object(capture,'run',side_effect=values), self.assertRaises(ValueError):
                    capture.host('apple-m2-aarch64')
            with patch.object(capture,'run',side_effect=['Apple M2','1','1','1']):
                self.assertEqual(capture.host('apple-m2-aarch64'),('Apple M2','+neon,+sha2'))

    def test_capture_boundaries(self):
        for failure in ('none','dirty','changed','recommit','source','output','wrong-backend','incomplete'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root/'source').write_text('original')
                output = root/'evidence.json'
                if failure == 'output': output.write_text('preserve')
                calls = {'status':0, 'commit':0}
                def run(command, env=None):
                    if command[:2] == ['git','status']:
                        calls['status'] += 1
                        return ' M source' if failure == 'dirty' or (failure == 'changed' and calls['status'] > 1) else ''
                    if command[:2] == ['git','rev-parse']:
                        calls['commit'] += 1
                        return 'b'*40 if failure == 'recommit' and calls['commit'] > 1 else 'a'*40
                    if command[0] == 'rustc': return 'rustc 1.98.1'
                    self.assertEqual(env['RUSTFLAGS'],'--cfg brynja_sha1_cpu_evidence -C target-feature=+sse2,+sha')
                    self.assertNotIn('CARGO_ENCODED_RUSTFLAGS',env)
                    if failure == 'source': (root/'source').write_text('changed')
                    if failure == 'incomplete': return 'PASS'
                    backend = 'legacy-aarch64-sha1' if failure == 'wrong-backend' else 'legacy-x86-sha1'
                    return 'SHA-1 CPU acceptance: PASS; backend='+backend+'; frozen_cases=20; nist_vectors=529\ncandidate=unadmitted'
                with patch.object(capture.policy,'ROOT',root), patch.object(capture.policy,'BOUND',['source']), \
                     patch.object(capture.policy,'validate'), patch.object(capture,'run',side_effect=run), \
                     patch.object(capture,'host',return_value=('AuthenticAMD','+sse2,+sha')):
                    args = SimpleNamespace(lane='amd-x86_64',output=output)
                    if failure == 'none':
                        capture.capture(args)
                        record = json.loads(output.read_text())
                        self.assertEqual(record['admission'],'unadmitted')
                        self.assertEqual(record['commit'],'a'*40)
                        self.assertFalse(record['fips_validated'])
                        self.assertNotIn('hostname',record)
                    else:
                        with self.assertRaises(ValueError): capture.capture(args)
                        if failure == 'output': self.assertEqual(output.read_text(),'preserve')
                        else: self.assertFalse(output.exists())

if __name__ == '__main__': unittest.main()
