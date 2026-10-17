"""Keep Apple resident consumer identity, graphs and results separate from strict."""
import copy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import legacy_strict_package as protected
from test_legacy_strict_package import document
from test_facade_keccak import rejected


def check(api):
    count = 0
    for family in ('sha1', 'md5'):
        good, roots, consumer = document(family, resident=True)
        protected.graph(api, good, roots, consumer, family, resident=True)
        rejected(lambda: protected.graph(api, good, roots, consumer, family))
        strict, strict_roots, strict_consumer = document(family)
        rejected(lambda: protected.graph(api, strict, strict_roots, strict_consumer, family, resident=True))
        for i in range(len(good['packages'])):
            for key, value in (('manifest_path', '/workspace/Cargo.toml'), ('source', 'registry+wrong'),
                               ('version', '9.9.9'), ('links', 'unexpected')):
                bad = copy.deepcopy(good)
                bad['packages'][i][key] = value
                rejected(lambda: protected.graph(api, bad, roots, consumer, family, resident=True))
                count += 1
            for feature in ('strict-execution', 'conformance-testing', 'runtime-execution'):
                bad = copy.deepcopy(good)
                bad['resolve']['nodes'][i]['features'].append(feature)
                rejected(lambda: protected.graph(api, bad, roots, consumer, family, resident=True))
                count += 1
            bad = copy.deepcopy(good)
            bad['resolve']['nodes'][i]['features'] = []
            rejected(lambda: protected.graph(api, bad, roots, consumer, family, resident=True))
            count += 1
        source = protected.cases.source(family, resident=True)
        assert 'strict_execution' not in source and 'macos_resident as api' in source
        assert 'STRICT_LEGACY_NATIVE:' not in source and 'RESIDENT_LEGACY_NATIVE:' in source
        assert len(protected.cases.negatives(family, resident=True)) == (7 if family == 'sha1' else 8)
        for source, _ in protected.cases.negatives(family, resident=True):
            assert 'strict_execution' not in source and 'macos_resident as api' in source
        for name, before, _, _ in protected.cases.mutations(family, True, resident=True):
            assert name.startswith('macos_resident/')
            assert (protected.shared.ROOT / f'crates/brynja-legacy-{family}-std/src' / name).read_text().count(before) == 1
        runtime(family)
    hosts()
    compiler_features()
    restoration()
    print(f'Apple legacy resident rejects {count} graph drifts, cross-profile graphs/markers, unsupported hosts and unrelated mutation failures')


def runtime(family):
    summary = 'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n'
    marker = f'RESIDENT_LEGACY_NATIVE: {family}; ' + ('corpus=169' if family == 'sha1' else 'lanes=712') + '\n'
    for native in (False, True):
        compiled = native or family == 'md5'
        output = (marker if compiled else '') + summary
        protected.runtime_check(SimpleNamespace(returncode=0, stdout=output), family, compiled, resident=True)
        for bad in (output + marker, output.replace('4 passed', '0 passed'), output.replace('0 ignored', '1 ignored'),
                    marker.replace('RESIDENT_LEGACY', 'STRICT_LEGACY') + summary, ('' if compiled else marker) + summary):
            rejected(lambda: protected.runtime_check(SimpleNamespace(returncode=0, stdout=bad), family, compiled, resident=True))


def compiler_features():
    for arch, family, features in (('x86_64', 'sha1', ('sha', 'sse2')), ('x86_64', 'md5', ('avx2',)),
                                    ('aarch64', 'sha1', ('neon', 'sha2')), ('aarch64', 'md5', ('neon',))):
        prefix = f'target_arch="{arch}"\n'
        full = prefix + ''.join(f'target_feature="{f}"\n' for f in features)
        assert protected.compiled_features(full, family)
        for feature in features:
            assert not protected.compiled_features(full.replace(f'target_feature="{feature}"\n', ''), family)
    for bad in ('', 'target_arch="riscv64"\n', 'target_arch="x86_64"\ntarget_arch="aarch64"\n'):
        rejected(lambda: protected.compiled_features(bad, 'sha1'))


def hosts():
    for system, machine, allowed in (('Darwin', 'arm64', True), ('Darwin', 'x86_64', False),
                                     ('Linux', 'aarch64', False), ('Windows', 'ARM64', False)):
        with patch.object(protected.platform, 'system', return_value=system), patch.object(protected.platform, 'machine', return_value=machine):
            if allowed:
                protected.require_host(True)
            else:
                rejected(lambda: protected.execute(None, Path('/unused'), '1.99.1', resident=True))


def restoration():
    with TemporaryDirectory(prefix='resident-legacy-regression-') as directory:
        root = Path(directory)
        for family in ('sha1', 'md5'):
            for name, before, after, test in protected.cases.mutations(family, True, resident=True):
                path = root / 'src' / name
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
                        return SimpleNamespace(returncode=0 if failure == 'survived' else 101, stdout='unrelated', stderr='')

                    with patch.object(protected.cases, 'mutations', return_value=[(name, before, after, test)]):
                        rejected(lambda: protected.mutants(SimpleNamespace(run=run), root,
                                 {f'brynja-legacy-{family}-std': root}, [], {}, family, True, resident=True))
                    assert path.read_text() == before
