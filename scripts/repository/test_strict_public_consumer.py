"""Cheap fail-closed regressions for strict scalar consumer orchestration."""
import copy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import strict_public_consumer as strict
from test_facade_keccak import rejected


def document():
    features = strict.expected_features()
    base = Path('/strict-public-test')
    roots = {name: base / name for name in features if name != 'facade-consumer'}
    consumer = base / 'consumer'
    versions = {'facade-consumer': '0.0.0', 'brynja-core': '0.9.0',
                'brynja-crypto-cpu': '0.1.1', 'brynja-crypto-cpu-std': '0.1.1'}
    packages = [dict(name=name, id=name, version=versions.get(name, '0.1.0'), source=None,
                     manifest_path=str((consumer if name == 'facade-consumer' else roots[name]) / 'Cargo.toml'),
                     targets=[dict(kind=['lib'], src_path=str((consumer if name == 'facade-consumer' else roots[name]) / 'src/lib.rs'))])
                for name in features]
    return dict(packages=packages, resolve=dict(root='facade-consumer',
                nodes=[dict(id=name, features=sorted(values)) for name, values in features.items()])), roots, consumer


def check(api):
    good, roots, consumer = document()
    strict.graph(api, good, roots, consumer)
    count = 0
    for i in range(len(good['packages'])):
        for key, value in (('manifest_path', '/checkout/Cargo.toml'), ('source', 'registry+wrong'),
                           ('version', '9.9.9'), ('links', 'unexpected')):
            bad = copy.deepcopy(good)
            bad['packages'][i][key] = value
            rejected(lambda: strict.graph(api, bad, roots, consumer))
            count += 1
        for feature in ('macos-resident', 'conformance-testing', 'runtime-execution', 'acceleration'):
            bad = copy.deepcopy(good)
            bad['resolve']['nodes'][i]['features'].append(feature)
            rejected(lambda: strict.graph(api, bad, roots, consumer))
            count += 1
        if good['resolve']['nodes'][i]['features']:
            bad = copy.deepcopy(good)
            bad['resolve']['nodes'][i]['features'] = []
            rejected(lambda: strict.graph(api, bad, roots, consumer))
            count += 1
    runtime()
    restoration()
    assert strict.cases.SOURCE.count('#[test]') == 7
    assert len(strict.cases.mutations()) == 16
    for name, before, _, _ in strict.cases.mutations():
        assert (strict.shared.ROOT / 'crates/brynja-crypto-cpu-std/src' / name).read_text().count(before) == 1
    assert strict.cases.replace_once('before', 'before', 'after') == 'after'
    for source in ('', 'before before'):
        rejected(lambda: strict.cases.replace_once(source, 'before', 'after'))
    print(f'Strict scalar consumer rejects {count} archive/feature drifts, population and adapter omissions; mutations restore on failures')


def runtime():
    summary = 'test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n'
    output = '\n'.join(strict.MARKERS) + '\n' + summary
    strict.runtime_check(SimpleNamespace(returncode=0, stdout=output))
    for bad in ('', summary, output + strict.MARKERS[0], output + summary,
                output.replace('7 passed', '0 passed'), output.replace('0 ignored', '1 ignored'),
                output.replace('0 filtered out', '1 filtered out'), output.replace('512 passed', '511 passed'),
                output + 'STRICT_UNEXPECTED: native\n'):
        rejected(lambda: strict.runtime_check(SimpleNamespace(returncode=0, stdout=bad)))
    rejected(lambda: strict.runtime_check(SimpleNamespace(returncode=1, stdout=output)))
    test = 'sha2_lifecycle'
    failed = (f'test {test} ... FAILED\n'
              'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 6 filtered out;\n')
    strict.mutation_result(SimpleNamespace(returncode=101, stdout=failed, stderr='panicked at fixture'), test)
    for code, out, err in ((0, failed, 'panicked at'), (-9, failed, 'panicked at'),
                           (101, failed.replace(test, 'different_test'), 'panicked at'),
                           (101, failed.replace('1 failed', '0 failed'), 'panicked at'),
                           (101, failed.replace('6 filtered out', '7 filtered out'), 'panicked at'),
                           (101, failed, 'compiler error'), (101, '', 'panicked at')):
        rejected(lambda: strict.mutation_result(SimpleNamespace(returncode=code, stdout=out, stderr=err), test))


def restoration():
    with TemporaryDirectory(prefix='strict-public-regression-') as directory:
        root = Path(directory)
        for name, before, after, test in strict.cases.mutations():
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
                                           stdout='unrelated failure', stderr='')

                with patch.object(strict.cases, 'mutations', return_value=[(name, before, after, test)]):
                    rejected(lambda: strict.mutants(SimpleNamespace(run=run), root,
                             {'brynja-crypto-cpu-std': root}, [], {}))
                assert path.read_text() == before
        source = root / 'src/lib.rs'
        source.write_text('original')

        def fail(*args, **kwargs):
            assert source.read_text() != 'original'
            raise ValueError('synthetic probe failure')

        rejected(lambda: strict.negatives(SimpleNamespace(run=fail), root, [], {}))
        assert source.read_text() == 'original'
