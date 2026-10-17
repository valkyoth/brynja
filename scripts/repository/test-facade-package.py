#!/usr/bin/env python3
"""Focused regressions for isolated facade acceptance (no compiler subprocess)."""
import copy
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
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


def archive_regressions():
    consumer = Path('/tmp/facade-archive-test/consumer')
    roots = {'brynja-crypto': Path('/tmp/facade-archive-test/unpacked/brynja-crypto-0.1.2')}
    baseline = document({'facade-consumer': [], 'brynja-crypto': []})
    baseline['resolve']['root'] = 'facade-consumer'
    for package, version, root in zip(baseline['packages'], ('0.0.0', '0.1.2'),
                                      (consumer, roots['brynja-crypto'])):
        package.update(version=version, manifest_path=str(root / 'Cargo.toml'),
                       targets=[{'kind': ['lib'], 'src_path': str(root / 'src/lib.rs')}])
    acceptance.archive_graph(baseline, roots, consumer)
    changes = (
        ('version', '0.1.3', 'archive version/source drift'),
        ('source', 'registry+https://example.invalid', 'archive version/source drift'),
        ('manifest_path', '/checkout/crates/brynja-crypto/Cargo.toml', 'dependency escaped'),
        ('manifest_path', str(roots['brynja-crypto'] / '../outside/Cargo.toml'), 'dependency escaped'),
        ('name', 'unregistered-local-crate', 'unregistered archive'),
        ('name', 'facade-consumer', 'duplicate packaged identity'),
        ('id', 'facade-consumer', 'duplicate packaged identity'),
        ('targets', [], 'native/absent targets'),
        ('links', 'native-library', 'native/absent targets'),
        ('targets', [{'kind': ['custom-build'], 'src_path': '/tmp/build.rs'}], 'build script/proc macro'),
        ('targets', [{'kind': ['proc-macro'], 'src_path': '/tmp/lib.rs'}], 'build script/proc macro'),
        ('targets', [{'kind': ['lib'], 'src_path': '/checkout/src/lib.rs'}], 'source target escaped'),
    )
    mutants = []
    for field, value, expected in changes:
        changed = copy.deepcopy(baseline)
        changed['packages'][1][field] = value
        mutants.append((changed, expected))
    for nodes in ([], baseline['resolve']['nodes'] * 2,
                  baseline['resolve']['nodes'] + [{'id': 'unknown', 'features': []}]):
        changed = copy.deepcopy(baseline)
        changed['resolve']['nodes'] = nodes
        mutants.append((changed, 'resolved package population'))
    changed = copy.deepcopy(baseline)
    changed['resolve']['root'] = 'brynja-crypto'
    mutants.append((changed, 'unexpected downstream root'))
    for changed, expected in mutants:
        try:
            acceptance.archive_graph(changed, roots, consumer)
        except ValueError as error:
            assert expected in str(error), error
        else:
            raise AssertionError('accepted archive provenance regression: ' + expected)
    print(f'Extracted archive binding rejects {len(mutants)} identity/path/target regressions')


def main():
    count = 0
    with patch('subprocess.run', side_effect=AssertionError('unexpected compilation')):
        archive_regressions()
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
        expected = 'test result: ok. 10 passed; 0 failed; 0 ignored;'
        for summary in (expected, '', expected.replace('10 passed', '0 passed'),
                        expected.replace('0 failed', '1 failed'),
                        expected.replace('0 ignored', '1 ignored')):
            with patch.object(acceptance, 'run', return_value=SimpleNamespace(stdout=summary)):
                if summary == expected:
                    acceptance.test_run(['cargo'], Path('.'), {}, 10)
                else:
                    try:
                        acceptance.test_run(['cargo'], Path('.'), {}, 10)
                    except ValueError as error:
                        assert 'test population changed' in str(error)
                    else:
                        raise AssertionError('accepted incomplete runtime population')
        assert acceptance.documentation().count('#[test]') == 2
        for text in ('', '```rust\nlet removed = ();\n```'):
            with patch.object(Path, 'read_text', return_value=text):
                try:
                    acceptance.documentation()
                except ValueError as error:
                    assert 'example population changed' in str(error)
                else:
                    raise AssertionError('accepted missing documentation examples')
    print(f'Facade package metadata rejects {count} graph regressions and hostile build environment')
    print('Runtime population and documentation extraction reject six omissions/failures')


if __name__ == '__main__':
    main()
