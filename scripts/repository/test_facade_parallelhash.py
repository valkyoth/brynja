"""Fail-closed regressions for ParallelHash packaged downstream acceptance."""
import copy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import facade_parallelhash_acceptance as acceptance
import facade_parallelhash_probes as probes
from test_facade_keccak import rejected


def graph_checks(api, document):
    names = {'brynja-crypto-cpu': [], 'brynja-crypto-cpu-std': ['keccak-hardened-batch'],
             'brynja-hash-parallel': ['hardened-batch-execution'],
             'brynja-hash-parallel-std': ['runtime-batch-execution']}
    baseline = document(names)
    api.graph(baseline, acceptance.FEATURES, hosted=True, threaded=True)
    for flags in ({}, {'hosted': True}, {'threaded': True}):
        rejected(lambda: api.graph(baseline, acceptance.FEATURES, **flags))
    rejected(lambda: api.graph(baseline, ['cpu'], hosted=True, threaded=True))
    for name, values in (('brynja-hash-parallel-std', []),
                         ('brynja-hash-parallel', []),
                         ('brynja-hash-parallel-std', ['runtime-batch-execution', 'conformance-testing']),
                         ('brynja-legacy-md5-std', [])):
        changed = names | {name: values}
        rejected(lambda: api.graph(document(changed), acceptance.FEATURES, hosted=True, threaded=True))
    for name in ('brynja-hash-parallel-std', 'brynja-crypto-cpu-std'):
        changed = {k: v for k, v in names.items() if k != name}
        rejected(lambda: api.graph(document(changed), acceptance.FEATURES, hosted=True, threaded=True))
    # Additional archive still binds version, local path, targets and graph identity.
    with TemporaryDirectory(prefix='facade-threaded-archive-') as directory:
        root = Path(directory)
        consumer = root / 'consumer'
        adapter = root / 'adapter'
        good = document({'facade-consumer': [], acceptance.ARCHIVE[0]: []})
        good['resolve']['root'] = 'facade-consumer'
        for package, version, path in zip(good['packages'], ('0.0.0', '0.1.0'), (consumer, adapter)):
            package.update(version=version, manifest_path=str(path / 'Cargo.toml'),
                           targets=[{'kind': ['lib'], 'src_path': str(path / 'src/lib.rs')}])
        roots = {acceptance.ARCHIVE[0]: adapter}
        api.archive_graph(good, roots, consumer)
        for field, value in (('version', '9.9.9'), ('source', 'registry+x'),
                             ('manifest_path', str(root / 'outside/Cargo.toml')),
                             ('targets', [{'kind': ['custom-build'], 'src_path': str(adapter / 'build.rs') }])):
            bad = copy.deepcopy(good)
            bad['packages'][1][field] = value
            rejected(lambda: api.archive_graph(bad, roots, consumer))
    print('Facade threaded opt-in rejects ten graph and four adapter archive regressions')


def check():
    names = ('parallel128', 'parallel256', 'parallelxof128', 'parallelxof256')
    cases = [(name, b'', 0, b'aaaa' if i < 12 else b'', 32 if i < 12 else 0, 1, 1, b'\x01')
             for name in names for i in range(64)]
    lines, expected, aligned = acceptance.render(cases)
    assert len(lines) == len(expected) == 256 and len(aligned) == 48
    for bad in (cases[:-1], cases + [cases[0]], [('unknown', *cases[0][1:])] + cases[1:],
                [('parallel256', *cases[0][1:])] + cases[1:],
                [(*cases[0][:-1], b'\x81')] + cases[1:],
                [(*cases[0][:-1], b'')] + cases[1:],
                [(names[0], b'', 0, b'', 32, 1, 1, b'\x01')] + cases[1:],
                [(names[0], b'', 0, b'aaaa', 32, 0, 1, b'\x01')] + cases[1:],
                [(names[0], b'', 0, b'', 0, 1, 1, b'\x01')] + cases[1:]):
        rejected(lambda: acceptance.render(bad))
    source = 'use brynja_hash_parallel::execution; use brynja_hash_parallel_std::execution; use brynja_crypto_cpu_std::execution;'
    for package, namespace in (('brynja', 'facade::crypto'), ('brynja-crypto', 'facade')):
        text = acceptance.rewrite(source, package)
        assert f'{namespace}::parallelhash::execution' in text and 'threads::execution' in text and 'host::execution' in text
    rejected(lambda: acceptance.rewrite(source, 'unknown'))
    rejected(lambda: acceptance.rewrite(source + ' use brynja_core::*;', 'brynja'))
    assert acceptance.probe_result('CPU:avx2\nROUTE:parallel:true\n') == ('avx2', True)
    for bad in ('', 'CPU:avx2', 'CPU:none\nROUTE:unknown:true',
                'CPU:other\nROUTE:parallel:true', 'CPU:neon\nROUTE:parallel:0',
                'CPU:neon\nROUTE:parallel:true\nextra'):
        rejected(lambda: acceptance.probe_result(bad))
    for vector in (False, True):
        calls = 17 if vector else 0
        good = SimpleNamespace(returncode=0, stdout='\n'.join(expected) + '\n',
            stderr=f'PARALLELHASH_BATCH_ORACLE: cases=256; vector_calls={calls}; workers=3; '
                   'max_thread_width=3; profiles=public,secret; cleanup=drop,scratch\n')
        acceptance.check_result(good, expected, 3, vector)
        for changes in ({'returncode': 1}, {'stdout': 'partial'}, {'stderr': ''},
                        {'stderr': good.stderr * 2},
                        {'stderr': good.stderr.replace('cases=256', 'cases=0')},
                        {'stderr': good.stderr.replace('workers=3', 'workers=1')},
                        {'stderr': good.stderr.replace('max_thread_width=3', 'max_thread_width=1')},
                        {'stderr': good.stderr.replace(f'vector_calls={calls}', f'vector_calls={0 if vector else 1}')},
                        {'stderr': good.stderr.replace('public,secret', 'public')}):
            bad = SimpleNamespace(**(vars(good) | changes))
            rejected(lambda: acceptance.check_result(bad, expected, 3, vector))
        rejected(lambda: acceptance.check_result(good, [], 3, vector))
    valid = SimpleNamespace(returncode=1, stdout='', stderr='Error: "field bound"\n')
    acceptance.check_failure(valid, 'field bound')
    for changes in ({'returncode': 0}, {'returncode': 101}, {'returncode': -9},
                    {'stdout': 'partial'}, {'stderr': 'error[E0308]'}, {'stderr': 'Error: "other"'}):
        bad = SimpleNamespace(**(vars(valid) | changes))
        rejected(lambda: acceptance.check_failure(bad, 'field bound'))
    restore()
    print('Facade ParallelHash harness rejects corpus/import/probe/output/thread/error drift and restores mutations/probes')


def restore():
    with TemporaryDirectory(prefix='facade-parallel-harness-') as directory:
        root = Path(directory)
        roots = {acceptance.ARCHIVE[0]: root}
        for attribute, helper, extra in (
            ('MUTANTS', acceptance.cleanup_mutants, ()),
            ('BEHAVIOR_MUTANTS', acceptance.behavior_mutants, ((['request'], ['answer'], [0]), True)),
        ):
            for mutant in getattr(acceptance, attribute):
                filename, before, *_ = mutant
                path = root / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                for failure in ('build', 'runtime', 'survived'):
                    path.write_text(before)

                    def run(command, *args, **kwargs):
                        assert path.read_text() != before
                        if failure == 'build':
                            raise ValueError('synthetic build failure')
                        if 'build' in command or '--no-run' in command:
                            return None
                        return SimpleNamespace(returncode=0 if failure == 'survived' else 101,
                                               stdout='', stderr='unrelated failure')

                    with patch.object(acceptance, attribute, (mutant,)):
                        rejected(lambda: helper(SimpleNamespace(run=run), root, roots, [],
                            {'CARGO_TARGET_DIR': str(root)}, *extra))
                    assert path.read_text() == before
        path = root / 'src/lib.rs'
        path.write_text('original')

        def fail(*args, **kwargs):
            raise ValueError('synthetic failure')

        def source(*args):
            path.write_text('probe')

        rejected(lambda: probes.negatives(SimpleNamespace(source=source, run=fail), root, 'brynja', [], {}))
        assert path.read_text() == 'original'
        fake = SimpleNamespace(PACKAGING_PACKAGES=(('original', '1', ()),), package_roots=fail)
        rejected(lambda: acceptance.package_roots(fake, root))
        assert fake.PACKAGING_PACKAGES == (('original', '1', ()),)

        def packaged(destination):
            assert destination == root
            assert fake.PACKAGING_PACKAGES == (('original', '1', ()), acceptance.ARCHIVE)
            return {'adapter': root}

        fake.package_roots = packaged
        assert acceptance.package_roots(fake, root) == {'adapter': root}
        assert fake.PACKAGING_PACKAGES == (('original', '1', ()),)
        fake.PACKAGING_PACKAGES += (acceptance.ARCHIVE,)
        rejected(lambda: acceptance.package_roots(fake, root))
