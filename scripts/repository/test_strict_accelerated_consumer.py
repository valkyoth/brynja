"""Route, corpus, graph and mutation-restoration regressions; no compiler calls."""
import copy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import strict_accelerated_consumer as accelerated
import test_strict_public_consumer as scalar_tests
from test_facade_keccak import rejected


def check(api):
    document, roots, consumer = scalar_tests.document()
    features = accelerated.expected_features()
    for node in document['resolve']['nodes']:
        node['features'] = sorted(features[node['id']])
    accelerated.graph(api, document, roots, consumer)
    count = 0
    for index in range(len(document['packages'])):
        for key, value in (('manifest_path', '/checkout/Cargo.toml'), ('source', 'registry+wrong'),
                           ('version', '9.9.9'), ('links', 'unexpected')):
            bad = copy.deepcopy(document)
            bad['packages'][index][key] = value
            rejected(lambda: accelerated.graph(api, bad, roots, consumer))
            count += 1
        for feature in ('conformance-testing', 'runtime-execution', 'macos-resident'):
            bad = copy.deepcopy(document)
            bad['resolve']['nodes'][index]['features'].append(feature)
            rejected(lambda: accelerated.graph(api, bad, roots, consumer))
            count += 1
        for feature in document['resolve']['nodes'][index]['features']:
            bad = copy.deepcopy(document)
            bad['resolve']['nodes'][index]['features'].remove(feature)
            rejected(lambda: accelerated.graph(api, bad, roots, consumer))
            count += 1
    routes()
    populations()
    adapters()
    restoration()
    print(f'Strict accelerated consumer rejects {count} archive/feature drifts, CPU/cfg/population substitutions, adapter drift and unrelated mutation failures')


def routes():
    for text in ('', 'CPU:x86_64:true:false\n', 'CPU:other:true:true:true\n',
                 'CPU:x86_64:true:true:false\n', 'CPU:aarch64:true:false:true\n',
                 'CPU:x86_64:true:false:true\nextra\n'):
        rejected(lambda: accelerated.probe(text))
    for arch, features, ready in (
        ('x86_64', ['sse2'], (False, False, False)),
        ('x86_64', ['sha', 'sse2'], (True, False, False)),
        ('x86_64', ['sha512', 'avx2', 'avx'], (False, True, True)),
        ('x86_64', ['sha512', 'avx2'], (False, False, False)),
        ('aarch64', ['neon', 'sha2'], (True, False, False)),
        ('aarch64', ['neon', 'sha3'], (False, True, True)),
        ('aarch64', ['sha2', 'sha3'], (False, False, False)),
    ):
        output = f'target_arch="{arch}"\n' + ''.join(f'target_feature="{f}"\n' for f in features)
        assert accelerated.compiled(output) == (arch, dict(zip(accelerated.sources.ROUTES, ready)))
    for output in ('', 'target_arch="riscv64"\n', 'target_arch="x86_64"\ntarget_arch="x86_64"\n'):
        rejected(lambda: accelerated.compiled(output))
    for text, expected in (
        ('CPU:x86_64:true:false:true\n', '+sha,+sse2,+avx,+avx2'),
        ('CPU:x86_64:false:true:true\n', '+sha512,+avx,+avx2'),
        ('CPU:aarch64:true:true:true\n', '+neon,+sha2,+sha3'),
    ):
        assert accelerated.flags(*accelerated.probe(text)) == expected
    rejected(lambda: accelerated.flags(*accelerated.probe('CPU:x86_64:false:false:false\n')))


def summary(n):
    return f'test result: ok. {n} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n'


def populations():
    for route in accelerated.sources.ROUTES:
        for ready in (True, False):
            marker = f'STRICT_COMPILED_ADMISSION: {route}; ready={str(ready).lower()}\n'
            good = summary(1) + marker
            accelerated.admission_check(SimpleNamespace(returncode=0, stdout=good), route, ready)
            for bad in ('', summary(1), good + marker, good.replace('0 ignored', '1 ignored'),
                        good.replace('1 passed', '0 passed'), good.replace(str(ready).lower(), str(not ready).lower())):
                rejected(lambda: accelerated.admission_check(SimpleNamespace(returncode=0, stdout=bad), route, ready))
        n = 5 if route == 'keccak' else 3
        good = summary(n) + '\n'.join(accelerated.sources.markers(route)) + '\n'
        accelerated.runtime_check(SimpleNamespace(returncode=0, stdout=good), route)
        for bad in ('', summary(n), good + summary(n), good.replace('0 ignored', '1 ignored'),
                    good.replace('0 filtered out', '1 filtered out'), good + accelerated.sources.markers(route)[0]):
            rejected(lambda: accelerated.runtime_check(SimpleNamespace(returncode=0, stdout=bad), route))
        test = 'hash_oracles'
        failed = f'test {test} ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; {n-1} filtered out;\n'
        accelerated.mutants.rejection(SimpleNamespace(returncode=101, stdout=failed, stderr='panicked at fixture'), test, n)
        for code, out, err in ((0, failed, 'panicked at'), (-9, failed, 'panicked at'),
                              (101, failed.replace(test, 'wrong_test'), 'panicked at'),
                              (101, failed.replace('1 failed', '0 failed'), 'panicked at'),
                              (101, failed.replace('0 ignored', '1 ignored'), 'panicked at'),
                              (101, failed, 'compiler failure')):
            rejected(lambda: accelerated.mutants.rejection(SimpleNamespace(returncode=code, stdout=out, stderr=err), test, n))
        for name, before, _, test in accelerated.mutants.mutations(route):
            assert (accelerated.scalar.shared.ROOT / 'crates/brynja-crypto-cpu-std/src' / name).read_text().count(before) == 1
            if '.update(part)' in before or 'copy_secret_region' in before:
                assert test in ('hash_oracles', 'keyed_oracles')  # Never self-referential reuse alone.
        assert len(accelerated.mutants.mutations(route)) == (12 if route == 'keccak' else 5)


def adapters():
    assert sum(c[0] for c in accelerated.sources.COUNTS.values()) == 662
    assert sum(c[1] for c in accelerated.sources.COUNTS.values()) == 240
    assert sum(c[2] for c in accelerated.sources.COUNTS.values()) == 4590
    with TemporaryDirectory(prefix='strict-accelerated-adapters-') as directory:
        root = Path(directory)
        roots = {'brynja-hash-sha2': accelerated.scalar.shared.ROOT / 'crates/brynja-hash-sha2'}
        for route in accelerated.sources.ROUTES:
            consumer = root / route
            accelerated.scalar.install(consumer, roots)
            accelerated.sources.install(consumer, route)
            source = (consumer / 'tests/acceptance.rs').read_text()
            assert source.count('#[test]') == (5 if route == 'keccak' else 3)
            assert source.count('s.quarantine();') == (3 if route == 'keccak' else 1)
            for name in ('families.rs', 'keyed.rs' if route == 'keccak' else 'bit_vectors.rs'):
                body = (consumer / 'src' / name).read_text()
                assert '::Session::new(' not in body
                assert 'crate::route::' in body
            for family in accelerated.sources.FAMILIES[route]:
                assert f'crate::route::{family}(' in source
            assert (consumer / 'tests/admission.rs').read_text().count('Backend(WrongArchitecture)') == len(accelerated.sources.FAMILIES[route])
            if route == 'wide':
                assert 'Algorithm::Sha512' in source and '[0;64]' in source
            if route == 'narrow':
                assert not (consumer / 'src/vectors/general-sha512-t-digest.txt').read_text()
        with patch.object(accelerated.sources.scalar, 'SOURCE', ''):
            try:
                accelerated.sources.lifecycle('narrow')
            except ValueError:
                pass
            else:
                raise AssertionError('missing lifecycle accepted')
    rejected(lambda: accelerated.sources.install(Path('/unused'), 'unknown'))


def restoration():
    with TemporaryDirectory(prefix='strict-accelerated-mutations-') as directory:
        root = Path(directory)
        for route in accelerated.sources.ROUTES:
            for name, before, after, test in accelerated.mutants.mutations(route):
                path = root / 'src' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                for failure in ('compile', 'unrelated', 'survived'):
                    path.write_text(before)

                    def run(command, *args, **kwargs):
                        assert path.read_text() == after
                        if failure == 'compile':
                            raise ValueError('synthetic build failure')
                        if '--no-run' in command:
                            return None
                        assert test in command and '--exact' in command
                        return SimpleNamespace(returncode=0 if failure == 'survived' else 101, stdout='', stderr='')

                    with patch.object(accelerated.mutants, 'mutations', return_value=[(name, before, after, test)]):
                        rejected(lambda: accelerated.mutants.run(SimpleNamespace(run=run), root,
                            {'brynja-crypto-cpu-std': root}, [], {}, route))
                    assert path.read_text() == before
