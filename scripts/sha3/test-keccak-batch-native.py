#!/usr/bin/env python3
"""Reject native evidence replay/coverage/claim and platform-selection regressions."""
import copy
import unittest
from unittest.mock import patch
import keccak_batch_native as native


def record(lane):
    arm = not lane.endswith('x86_64')
    kernel, width = ('Neon', 2) if arm else ('Avx2', 4)
    system = 'Darwin' if lane == 'apple-m2-aarch64' else 'Linux'
    target = 'aarch64-apple-darwin' if system == 'Darwin' else ('aarch64' if arm else 'x86_64') + '-unknown-linux-gnu'
    results = dict.fromkeys(native.RESULTS, 'test result: ok. 3 passed; 0 failed;')
    results['vector'] += f'\nKECCAK_BATCH_NATIVE: {kernel}; calls=1024; width={width}\nKECCAK_BATCH_API: {kernel}; comparisons=512\n'
    for mode in ('portable', 'prefer', 'required'):
        results['oracle_' + mode] = f'Keccak batch: 1024 independent outputs and six malformed requests PASS; mode={mode}; vector_calls={0 if mode == "portable" else 1}'
    results['packaged'] = "Packaged Keccak batch: 23 negatives, 10 compiled mutants rejected; modes=('portable', 'prefer', 'required')"
    results['packaged'] += '\nPackaged Keccak batch: one compiled scalar-only false-route mutant rejected'
    results['codegen'] = f'Keccak independent SIMD codegen: PASS; 1.98.1; {target}'
    rows, total = [], 0
    for name, (rate, bits) in native.ALGORITHMS.items():
        for size in (0, rate, 4096, 16384):
            for lanes in range(1, 5):
                calls = 0 if lanes < width else 7
                total += calls
                rows.append(f'KECCAK_BATCH_BENCH: algorithm={name}; bytes_max={size}; lanes={lanes}; output_bits={bits}; mode=Prefer; kernel=Some({kernel}); samples=7; portable_median_ns=10; selected_median_ns=20; vector_calls={calls}')
    rows.append(f'KECCAK_BATCH_BENCHMARK: PASS; cases=128; vector_calls={total}; threshold=caller-selected; public-only')
    results['benchmark'] = '\n'.join(rows)
    return dict(schema=1, version='0.24.47', lane=lane, commit='a' * 40,
        compiler=f'release: 1.98.1\nhost: {target}', cpu='test CPU', system=system,
        features='+neon' if arm else '+avx,+avx2', source_sha512={'test': 'a' * 128}, results=results,
        native='operator-self-attested', profile='ordinary-public-only', independent_review=False,
        fips_validated=False, migration_safety='deployment obligation; not independently proven')


class NativeTests(unittest.TestCase):
    def test_all_lanes_and_tampering(self):
        for lane in native.LANES:
            good = record(lane)
            native.validate(good, good['source_sha512'])
            replacements = dict(schema=True, version='0.24.46', lane='qemu', commit='invalid',
                compiler='release: 1.98.1', cpu='', system='wrong', features='+fake', source_sha512={},
                native='emulated', profile='hardened', independent_review=True, fips_validated=True, migration_safety='proven')
            for key, value in replacements.items():
                bad = copy.deepcopy(good)
                bad[key] = value
                with self.subTest(lane=lane, field=key), self.assertRaises(ValueError): native.validate(bad, good['source_sha512'])
            for key in native.RESULTS:
                for value in ('', 'PASS'):
                    bad = copy.deepcopy(good)
                    bad['results'][key] = value
                    with self.subTest(lane=lane, result=key, value=value), self.assertRaises(ValueError): native.validate(bad, good['source_sha512'])
            for before, after in (('calls=1024', 'calls=0'), ('comparisons=512', 'comparisons=0'),
                                  ('10 compiled mutants', '9 compiled mutants'), ('cases=128', 'cases=127')):
                bad = copy.deepcopy(good)
                bad['results'] = {k: v.replace(before, after) for k, v in bad['results'].items()}
                self.assertNotEqual(bad, good)
                with self.assertRaises(ValueError): native.validate(bad, good['source_sha512'])
            bad = copy.deepcopy(good)
            rows = bad['results']['benchmark'].splitlines()
            rows[1] = rows[0]
            bad['results']['benchmark'] = '\n'.join(rows)
            with self.assertRaises(ValueError): native.validate(bad, good['source_sha512'])

    def test_platform_mismatch_and_mixed_cpu_features(self):
        for cpu in ('', 'vendor_id : GenuineIntel\nflags : avx',
                    'vendor_id : GenuineIntel\nflags : avx avx2\nflags : avx',
                    'vendor_id : AuthenticAMD\nflags : avx avx2'):
            with patch.object(native.platform, 'machine', return_value='x86_64'), \
                 patch.object(native.platform, 'system', return_value='Linux'), \
                 patch.object(native.Path, 'read_text', return_value=cpu):
                with self.assertRaises(ValueError): native.host('intel-x86_64')
        with patch.object(native.platform, 'machine', return_value='x86_64'), \
             patch.object(native.platform, 'system', return_value='Linux'):
            with self.assertRaises(ValueError): native.host('apple-m2-aarch64')


if __name__ == '__main__': unittest.main()
