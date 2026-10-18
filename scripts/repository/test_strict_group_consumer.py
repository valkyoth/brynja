"""Focused group harness regressions; no compiler or native subprocesses."""
import copy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import strict_group_consumer as groups
import test_strict_public_consumer as scalar_tests
from test_facade_keccak import rejected
from test_strict_accelerated_consumer import summary


def check(api):
    document, roots, consumer = scalar_tests.document()
    expected = groups.accelerated.expected_features()
    expected['facade-consumer'] = {'native'}
    for node in document['resolve']['nodes']:
        node['features'] = sorted(expected[node['id']])
    groups.graph(api, document, roots, consumer)
    count = 0
    for i, package in enumerate(document['packages']):
        for key, value in (('source', 'registry+wrong'), ('version', '9.9.9'),
                           ('manifest_path', '/workspace/Cargo.toml'), ('links', 'unexpected')):
            bad = copy.deepcopy(document)
            bad['packages'][i][key] = value
            rejected(lambda: groups.graph(api, bad, roots, consumer))
            count += 1
        for value in ('conformance-testing', 'macos-resident', 'runtime-execution'):
            bad = copy.deepcopy(document)
            bad['resolve']['nodes'][i]['features'].append(value)
            rejected(lambda: groups.graph(api, bad, roots, consumer))
            count += 1
        for value in expected[package['id']]:
            bad = copy.deepcopy(document)
            bad['resolve']['nodes'][i]['features'].remove(value)
            rejected(lambda: groups.graph(api, bad, roots, consumer))
            count += 1
    populations()
    sources()
    restoration()
    companion_restoration()
    print(f'Strict group consumers reject {count} archive/feature drifts, false/skipped runtime populations, adapter drift and surviving/unrelated mutants; sources restore')


def populations():
    for native in (False, True):
        markers = [f'STRICT_GROUP_BATCH: scalar=662; SIMD={616 if native else 0}; ineligible={46 if native else 0}',
            f'STRICT_GROUP_PARALLEL: scalar=548; single={548 if native else 0}; SIMD={548 if native else 0}; workers=1,3',
            'STRICT_GROUP_BITS: named=240; general-t=4590; sparse scalar slots',
            f'STRICT_GROUP_MIXED: scalar=522; SIMD={522 if native else 0}; lanes={4192 if native else 2096}; general-t=510']
        text = summary(6) + '\n'.join(markers) + '\n'
        groups.runtime_check(SimpleNamespace(returncode=0, stdout=text), native)
        for bad in ('', summary(6), text + markers[0], text.replace('0 ignored', '1 ignored'),
                    text.replace('6 passed', '5 passed'), text.replace('scalar=662', 'scalar=0'),
                    text.replace('workers=1,3', 'workers=1'), text.replace('general-t=510', 'general-t=509')):
            rejected(lambda: groups.runtime_check(SimpleNamespace(returncode=0, stdout=bad), native))
        rejected(lambda: groups.runtime_check(SimpleNamespace(returncode=0, stdout=text), not native))
    for arch, kernel in (('X86Keccak', 'Avx2'), ('ArmKeccak', 'Neon')):
        text = summary(1).replace('0 filtered out', '37 filtered out')
        markers = [f'STRICT_PARALLELHASH: Single({arch}); differential=288',
                   f'STRICT_PARALLELHASH: Batch({kernel}); differential=288']
        text += '\n'.join(markers) + '\n'
        groups.probes.instrumented_check(SimpleNamespace(returncode=0, stdout=text))
        for bad in ('', summary(1), text + markers[0], text.replace('0 ignored', '1 ignored'),
                    text.replace('differential=288', 'differential=0')):
            rejected(lambda: groups.probes.instrumented_check(SimpleNamespace(returncode=0, stdout=bad)))


def sources():
    batch, parallel = groups.sources.batch_source(), groups.sources.parallel_source()
    assert 'brynja_strict::batch' in batch and 'brynja_strict::parallelhash' in parallel
    assert 'brynja_hash_' not in batch + parallel and 'macos_resident' not in batch + parallel
    assert 'assert_eq!(calls>0,simd)' in batch
    assert 'counts,[548;3]' not in parallel and 'workers in [1,3]' in parallel
    assert 'if cfg!(feature="native")' in parallel
    assert 'CompiledSession::new' in parallel and 'LeafRoute::Batch' in parallel
    assert groups.sources.LIFECYCLE.count('#[test]') == 2
    for marker in ('core::mem::forget', 'catch_unwind', 'Error::Quarantined', 'Error::Cancelled', 'Error::OutputLength'):
        assert marker in groups.sources.LIFECYCLE
    assert 'assert_eq!((named,general),(240,4590))' in groups.sources.BITS
    assert 'assert_eq!(pools.each_ref().map(|p|p.len()),[2,514,6])' in groups.sources.strict_group_mixed.SOURCE
    for module, name in ((groups.sources.batch_oracle, 'SOURCE'), (groups.sources.parallel_oracle, 'SOURCE')):
        with patch.object(module, name, ''):
            rejected(groups.sources.batch_source if module is groups.sources.batch_oracle else groups.sources.parallel_source)
    for native in (False, True):
        assert len(groups.probes.mutations(native)) == (14 if native else 9)
        for package, name, before, after, test in groups.probes.mutations(native):
            body = (groups.scalar.shared.ROOT / 'crates' / package / 'src' / name).read_text()
            assert before in body and before != after
            if 'copy_secret_region' in before or 'Report::$kind' in before:
                assert test in ('batch_oracles', 'parallel_oracles')


def restoration():
    with TemporaryDirectory(prefix='strict-group-regressions-') as directory:
        root = Path(directory)
        for mutation in groups.probes.mutations(True):
            package, name, before, after, test = mutation
            path = root / package / 'src' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            for failure in ('compile', 'unrelated', 'survived'):
                path.write_text(before)

                def run(command, *args, **kwargs):
                    assert path.read_text() == after
                    if failure == 'compile':
                        raise ValueError('synthetic compile failure')
                    if '--no-run' in command:
                        return None
                    assert test in command and '--exact' in command
                    return SimpleNamespace(returncode=0 if failure == 'survived' else 101, stdout='', stderr='')

                with patch.object(groups.probes, 'mutations', return_value=[mutation]):
                    rejected(lambda: groups.probes.mutants(SimpleNamespace(run=run), root, {package: root / package}, [], {}, True))
                assert path.read_text() == before


def companion_restoration():
    """Every companion failure restores both the source and the manifest."""
    package = 'brynja-hash-parallel-std'
    source = groups.scalar.shared.ROOT / 'crates' / package
    with TemporaryDirectory(prefix='strict-group-companion-') as directory:
        root = Path(directory)
        worker = root / 'src/strict_execution/compiled/worker.rs'
        worker.parent.mkdir(parents=True)
        pristine = (source / 'src/strict_execution/compiled/worker.rs').read_text()
        manifest = root / 'Cargo.toml'
        original = '[package]\nname="synthetic"\nversion="0.0.0"\n'
        # Lockfile, initial baseline, mutant compilation, mutant execution,
        # restored baseline, and the same four operations in release.
        for fail_at in range(1, 10):
            manifest.write_text(original)
            worker.write_text(pristine)
            calls = 0

            def run(command, *args, **kwargs):
                nonlocal calls
                calls += 1
                assert '[patch.crates-io]' in manifest.read_text()
                if calls == fail_at:
                    raise ValueError('synthetic companion failure')
                if 'generate-lockfile' in command or '--no-run' in command:
                    return None
                if worker.read_text() != pristine:
                    test = 'strict_execution::compiled::tests::native::actual_parallel_single_and_simd_waves_match_all_identities'
                    return SimpleNamespace(returncode=101,
                        stdout=f'test {test} ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;\n',
                        stderr='VECTOR_CALLS.load')
                return SimpleNamespace(returncode=0, stdout=summary(1) +
                    'STRICT_PARALLELHASH: Single(X86Keccak); differential=288\n'
                    'STRICT_PARALLELHASH: Batch(Avx2); differential=288\n')

            rejected(lambda: groups.probes.parallel_instrumented(SimpleNamespace(run=run), {package: root}, [], {}))
            assert calls == fail_at
            assert worker.read_text() == pristine
            assert manifest.read_text() == original
