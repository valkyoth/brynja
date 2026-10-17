#!/usr/bin/env python3
"""Focused regressions for isolated facade acceptance (no compiler subprocess)."""
import copy
import importlib.util
import os
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'facade_package', Path(__file__).with_name('check-facade-package.py'))
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


def document(names):
    return {'packages': [{'id': name, 'name': name, 'source': None} for name in names],
            'resolve': {'nodes': [{'id': name, 'features': features}
                                  for name, features in names.items()]}}


def rejects(doc, features, expected):
    try:
        acceptance.graph(doc, features)
    except ValueError as error:
        assert expected in str(error), error
    else:
        raise AssertionError('accepted graph regression: ' + expected)


def main():
    count = 0
    with patch('subprocess.run', side_effect=AssertionError('unexpected compilation')):
        baseline = document({'facade-consumer': [], 'brynja': [], 'brynja-crypto': []})
        acceptance.graph(baseline, [])
        for source in ('registry+https://example.invalid', 'git+https://example.invalid'):
            changed = copy.deepcopy(baseline)
            changed['packages'][1]['source'] = source
            rejects(changed, [], 'registry/git dependency')
            count += 1
        for name in ('brynja-crypto-cpu-std', 'brynja-hash-parallel-std',
                     'brynja-legacy', 'brynja-legacy-sha1'):
            rejects(document({name: []}), [], 'host or legacy')
            count += 1
        rejects(document({'brynja-hash-sha2': ['conformance-testing']}), [], 'conformance')
        rejects(document({'brynja-crypto-cpu': []}), [], 'CPU opt-in')
        rejects(baseline, ['cpu'], 'CPU opt-in')
        acceptance.graph(document({'brynja-crypto-cpu': []}), ['cpu'])
        count += 3
        for feature, (owner, leaf) in acceptance.policy.LEAVES.items():
            names = {owner: [leaf]}
            if feature != 'general-sha512-t':
                names['brynja-crypto-cpu'] = []
            acceptance.graph(document(names), [feature])
            names[owner] = []
            rejects(document(names), [feature], 'missing resolved leaf')
            count += 1
        with patch.dict(os.environ, {'RUSTFLAGS': '--cfg brynja_cpu_evidence',
                                    'CARGO_ENCODED_RUSTFLAGS': '-Ctarget-feature=+avx2',
                                    'CARGO_BUILD_TARGET': 'wrong-target',
                                    'CARGO_BUILD_BUILD_DIR': '/stale/cache',
                                    'BRYNJA_REQUIRE_SHA256_BATCH': '1'}):
            clean = acceptance.clean_environment(Path('/tmp/facade-env-test'))
            assert not any(k.startswith(('RUST', 'BRYNJA_')) for k in clean)
            assert set(k for k in clean if k.startswith('CARGO_')) == {
                'CARGO_HOME', 'CARGO_TARGET_DIR'}
    print(f'Facade package metadata rejects {count} graph regressions and hostile build environment')


if __name__ == '__main__':
    main()
