"""Archive, execution and failure-restoration regressions for strict consumers."""
import copy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import legacy_strict_package as strict
from test_facade_keccak import rejected


def document(family, resident=False):
    features = strict.expected_features(family, resident)
    base = Path('/strict-legacy-test')
    roots = {name: base / name for name in features if name != 'facade-consumer'}
    consumer = base / 'consumer'
    versions = {'facade-consumer': '0.0.0', 'brynja-core': '0.10.0',
                'brynja-crypto-cpu': '0.2.0', 'brynja-crypto-cpu-std': '0.2.0'}
    packages = [dict(name=name, id=name, version=versions.get(name, '0.1.0'), source=None,
                     manifest_path=str((consumer if name == 'facade-consumer' else roots[name]) / 'Cargo.toml'),
                     targets=[dict(kind=['lib'], src_path=str((consumer if name == 'facade-consumer' else roots[name]) / 'src/lib.rs'))])
                for name in features]
    return dict(packages=packages, resolve=dict(root='facade-consumer',
                nodes=[dict(id=name, features=sorted(values)) for name, values in features.items()])), roots, consumer


def check(api):
    count = 0
    for family in ('sha1', 'md5'):
        good, roots, consumer = document(family)
        strict.graph(api, good, roots, consumer, family)
        for i in range(len(good['packages'])):
            for key, value in (('manifest_path', '/workspace/Cargo.toml'), ('source', 'registry+wrong'),
                               ('version', '9.9.9'), ('links', 'unexpected')):
                bad = copy.deepcopy(good)
                bad['packages'][i][key] = value
                rejected(lambda: strict.graph(api, bad, roots, consumer, family))
                count += 1
            for feature in ('macos-resident', 'conformance-testing', 'runtime-execution'):
                bad = copy.deepcopy(good)
                bad['resolve']['nodes'][i]['features'].append(feature)
                rejected(lambda: strict.graph(api, bad, roots, consumer, family))
                count += 1
            bad = copy.deepcopy(good)
            bad['resolve']['nodes'][i]['features'] = []
            rejected(lambda: strict.graph(api, bad, roots, consumer, family))
            count += 1
        assert len(strict.cases.owners(family)) == (3 if family == 'sha1' else 4)
        assert len(strict.cases.negatives(family)) == (7 if family == 'sha1' else 8)
        assert len(strict.cases.mutations(family, False)) == 3
        assert len(strict.cases.mutations(family, True)) == (5 if family == 'sha1' else 6)
        for name, before, _, _ in strict.cases.mutations(family, True):
            assert (strict.shared.ROOT / f'crates/brynja-legacy-{family}-std/src' / name).read_text().count(before) == 1
        runtime(family)
    restoration()
    print(f'Strict legacy consumer rejects {count} archive/feature drifts, skipped/native populations and unrelated mutant failures; sources restore')


def runtime(family):
    summary = 'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n'
    marker = f'STRICT_LEGACY_NATIVE: {family}; ' + ('corpus=169' if family == 'sha1' else 'lanes=712') + '\n'
    for arch in ('x86_64', 'aarch64'):
        for native in (False, True):
            compiled = native or (family == 'md5' and arch == 'aarch64')
            output = (marker if compiled else '') + summary
            strict.runtime_check(SimpleNamespace(returncode=0, stdout=output), family, compiled)
            for bad in ('', output.replace('4 passed', '0 passed'), output.replace('0 ignored', '1 ignored'),
                        output + marker, output.replace('0 filtered out', '1 filtered out'),
                        ('' if compiled else marker) + summary, output + 'STRICT_LEGACY_NATIVE: bogus\n'):
                rejected(lambda: strict.runtime_check(SimpleNamespace(returncode=0, stdout=bad), family, compiled))


def restoration():
    with TemporaryDirectory(prefix='strict-legacy-regression-') as directory:
        root = Path(directory)
        for family in ('sha1', 'md5'):
            for name, before, after, test in strict.cases.mutations(family, True):
                path = root / 'src' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                for failure in ('compile', 'unrelated', 'survived'):
                    path.write_text(before)

                    def run(command, *args, **kwargs):
                        assert path.read_text() == after
                        if failure == 'compile':
                            raise ValueError('synthetic compilation failure')
                        if '--no-run' in command:
                            return None
                        assert test in command and '--exact' in command
                        return SimpleNamespace(returncode=0 if failure == 'survived' else 101,
                                               stdout='unrelated error', stderr='')

                    with patch.object(strict.cases, 'mutations', return_value=[(name, before, after, test)]):
                        rejected(lambda: strict.mutants(SimpleNamespace(run=run), root,
                                 {f'brynja-legacy-{family}-std': root}, [], {}, family, True))
                    assert path.read_text() == before
        source = root / 'src/lib.rs'
        source.write_text('original')

        def fail(*args, **kwargs):
            assert source.read_text() != 'original'
            raise ValueError('synthetic probe failure')

        rejected(lambda: strict.negatives(SimpleNamespace(run=fail), root, [], {}, 'sha1'))
        assert source.read_text() == 'original'
