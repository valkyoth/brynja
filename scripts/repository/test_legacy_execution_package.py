"""Regression tests for legacy archive binding, populations and restoration."""
import copy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import legacy_execution_package as legacy
from test_facade_keccak import rejected


def document(family, base):
    leaf = 'brynja-legacy-' + family
    features = {'facade-consumer': ['execution', 'runtime-execution'], 'brynja-core': ['default'],
                'brynja-hash-core': ['default'], leaf: ['default', 'cpu', 'execution', *(['batch'] if family == 'md5' else [])],
                leaf + '-std': ['runtime-execution']}
    roots = {name: base / name for name in features if name != 'facade-consumer'}
    consumer = base / 'consumer'
    packages = []
    for name in features:
        root = consumer if name == 'facade-consumer' else roots[name]
        version = '0.0.0' if name == 'facade-consumer' else '0.9.0' if name == 'brynja-core' else '0.1.0'
        packages.append(dict(id=name, name=name, version=version, source=None,
                             manifest_path=str(root / 'Cargo.toml'),
                             targets=[dict(kind=['lib'], src_path=str(root / 'src/lib.rs'))]))
    return dict(packages=packages, resolve=dict(root='facade-consumer',
                nodes=[dict(id=name, features=values) for name, values in features.items()])), roots, consumer


def check(api):
    count = 0
    for family in ('sha1', 'md5'):
        good, roots, consumer = document(family, Path('/legacy-archive-regression'))
        legacy.graph(api, good, roots, consumer, family)
        for index in range(len(good['packages'])):
            for key, value in (('version', '9.9.9'), ('source', 'registry+unexpected'),
                               ('manifest_path', '/workspace/Cargo.toml'), ('links', 'native'),
                               ('targets', [dict(kind=['custom-build'], src_path='/workspace/build.rs')])):
                changed = copy.deepcopy(good)
                changed['packages'][index][key] = value
                rejected(lambda: legacy.graph(api, changed, roots, consumer, family))
                count += 1
            changed = copy.deepcopy(good)
            changed['resolve']['nodes'][index]['features'].append('conformance-testing')
            rejected(lambda: legacy.graph(api, changed, roots, consumer, family))
            count += 1
        for index in (0, 3, 4):
            changed = copy.deepcopy(good)
            changed['resolve']['nodes'][index]['features'] = []
            rejected(lambda: legacy.graph(api, changed, roots, consumer, family))
            count += 1
        changed = copy.deepcopy(good)
        changed['packages'][3]['name'] = 'brynja-crypto'
        rejected(lambda: legacy.graph(api, changed, roots, consumer, family))
        count += 1
    for expected in (1, 3, 4):
        summary = f'test result: ok. {expected} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n'
        good = SimpleNamespace(returncode=0, stdout=summary)
        legacy.population(good, expected)
        for bad in ('', summary * 2, summary.replace(f'{expected} passed', '0 passed'),
                    summary.replace('0 failed', '1 failed'), summary.replace('0 ignored', '1 ignored'),
                    summary.replace('0 filtered out', '1 filtered out')):
            rejected(lambda: legacy.population(SimpleNamespace(returncode=0, stdout=bad), expected))
        rejected(lambda: legacy.population(SimpleNamespace(returncode=101, stdout=summary), expected))
    for family, xflags, aflags in (('sha1', '+sha,+sse2', '+neon,+sha2'), ('md5', '+avx2', '+neon')):
        assert legacy.native_flags('CPU:x86_64:true:true\n', family) == xflags
        assert legacy.native_flags('CPU:aarch64:true:true\n', family) == aflags
        for bad in ('', 'CPU:other:false:false\n', 'CPU:other:true:true\n', 'CPU:x86_64:false:false\n',
                    'CPU:x86_64:true:true\nextra\n', 'CPU:x86_64:1:1\n'):
            rejected(lambda: legacy.native_flags(bad, family))
        unavailable = 'CPU:x86_64:false:true\n' if family == 'sha1' else 'CPU:x86_64:true:false\n'
        rejected(lambda: legacy.native_flags(unavailable, family))
    restoration()
    negative_population()
    print(f'Legacy ordinary acceptance rejects {count} archive/graph regressions, skipped populations, native probe drift and surviving mutants; restoration verified')


def restoration():
    with TemporaryDirectory(prefix='legacy-mutation-regression-') as directory:
        root = Path(directory)
        for family in ('sha1', 'md5'):
            for filename, before, after in legacy.cases.mutations(family, True):
                path = root / 'src' / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                for failure in ('compile', 'runtime', 'survived'):
                    path.write_text(before)

                    def run(command, *args, **kwargs):
                        assert path.read_text() == after
                        if failure == 'compile':
                            raise ValueError('synthetic build failure')
                        if '--no-run' in command:
                            return None
                        return SimpleNamespace(returncode=0 if failure == 'survived' else 101, stdout='unrelated failure', stderr='')

                    with patch.object(legacy.cases, 'mutations', return_value=[(filename, before, after)]):
                        rejected(lambda: legacy.mutants(SimpleNamespace(run=run), root,
                                 {'brynja-legacy-' + family: root}, [], {}, family, True))
                    assert path.read_text() == before
        path = root / 'src/lib.rs'
        path.write_text('original')

        def fail(*args, **kwargs):
            assert path.read_text() != 'original'
            raise ValueError('synthetic negative build failure')

        rejected(lambda: legacy.negatives(SimpleNamespace(run=fail), root, [], {}, 'sha1'))
        assert path.read_text() == 'original'


def negative_population():
    with TemporaryDirectory(prefix='legacy-negative-population-') as directory:
        root = Path(directory)
        (root / 'src').mkdir()
        source = root / 'src/lib.rs'
        source.write_text('original')
        for family, expected in (('sha1', 18), ('md5', 13)):
            seen = []

            def run(command, *args, **kwargs):
                text = source.read_text()
                if '--message-format=json' not in command:
                    assert 'pub fn present' in text
                    return None
                code = ('E0133' if 'from_platform' in text else 'E0624' if '.session()' in text else
                        'E0061' if 'fn bad(e:' in text else 'E0277')
                seen.append(code)
                return SimpleNamespace(code=code)

            with patch.object(legacy, 'diagnostic', side_effect=lambda result, code: result.code == code):
                legacy.negatives(SimpleNamespace(run=run), root, [], {}, family)
            assert len(seen) == expected and seen[-3:] == ['E0133', 'E0624', 'E0061']
            assert source.read_text() == 'original'
