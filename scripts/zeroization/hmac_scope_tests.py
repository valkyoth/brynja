"""HMAC integration classification: graph, feature, source and Git regressions."""
import json
import subprocess
import tempfile
from pathlib import Path

import miri_scope as scope
import scope_hmac as hmac
import scope_inputs as inputs


def lock(rows):
    return ('version=4\n' + ''.join('[[package]]\n' + ''.join(
        f'{key}={json.dumps(value)}\n' for key, value in row.items()) for row in rows)).encode()


def package(name, *edges, **extra):
    return {'name': name, 'version': '0.1.0', 'dependencies': list(edges), **extra}


def rejected(call):
    try:
        call()
    except (ValueError, KeyError, TypeError):
        return
    raise AssertionError('invalid HMAC scope accepted')


def graph_tests():
    core = package('brynja-core')
    sha2 = package('brynja-hash-sha2', 'brynja-core')
    sha3 = package('brynja-hash-sha3', 'brynja-core')
    leaf = package(hmac.LEAF, 'brynja-hash-sha2', 'brynja-hash-sha3')
    crypto = package('brynja-crypto', 'brynja-hash-sha2')
    hosted = package('brynja-crypto-cpu-std', 'brynja-hash-sha2')
    base = [core, sha2, sha3, crypto, hosted]
    new = [core, sha2, sha3, leaf,
           dict(crypto, dependencies=['brynja-hash-sha2', hmac.LEAF]),
           dict(hosted, dependencies=['brynja-hash-sha2', hmac.LEAF])]
    for old, current in ((base, new), (new, base)):
        assert inputs.lock_groups(lock(old), lock(current)) == {'hmac'}
    # Changed implementation edges still propagate into the HMAC family and
    # hosted consumer; removing an edge must not hide the original consumer.
    changed = [dict(row, dependencies=[]) if row['name'] == 'brynja-hash-sha2' else row for row in new]
    for old, current in ((new, changed), (changed, new)):
        assert inputs.lock_groups(lock(old), lock(current)) == {'sha2', 'static_cpu', 'hmac'}
    registry = package('external', source='registry+https://example.invalid', checksum='a')
    with_external = [dict(row, dependencies=['external']) if row['name'] == hmac.LEAF else row
                     for row in new] + [registry]
    updated = [dict(row, checksum='b') if row['name'] == 'external' else row for row in with_external]
    assert inputs.lock_groups(lock(with_external), lock(updated)) == {'hmac'}
    for extra in ({'source': 'git+https://example.invalid'}, {'checksum': 'fake'}, {'replace': 'other'}):
        altered = [dict(row, **extra) if row['name'] == 'brynja-crypto' else row for row in new]
        # A sourced facade is not a local facade-edge exemption.
        if 'source' in extra:
            assert not hmac.lock_edge_only('brynja-crypto',
                {'name': 'brynja-crypto', 'dependencies': []}, altered[-2])
        else:
            rejected(lambda: inputs.lock_groups(lock(base), lock(altered)))
    for edges in (['brynja-core', hmac.LEAF], [hmac.LEAF, hmac.LEAF], ['missing']):
        altered = [dict(row, dependencies=edges) if row['name'] == 'brynja-crypto' else row for row in new]
        rejected(lambda: inputs.lock_groups(lock(base), lock(altered)))
    rejected(lambda: inputs.lock_groups(lock(base), lock(new + [package('unknown')])))
    rejected(lambda: inputs.lock_groups(lock(base), lock([r for r in new if r['name'] != hmac.LEAF])))
    rejected(lambda: inputs.lock_groups(lock(base), lock([r for r in new if r['name'] != 'brynja-crypto'])))


def manifest_tests():
    path = 'crates/brynja-strict/Cargo.toml'
    after = (scope.ROOT / path).read_bytes()
    before = after.replace(b', "brynja-crypto-cpu-std/strict-hmac-acceleration"', b'').replace(b', "strict-hmac"', b'')
    assert before != after
    assert hmac.manifest_only(path, before, after)
    assert hmac.manifest_only(path, after, before)
    for changed in (after.replace(b'"strict-hmac"', b'"hmac-execution"'),
                    after.replace(b'"strict-hmac"', b'"strict-hmac", "strict-hmac"'),
                    after.replace(b'strict-hmac-acceleration', b'macos-resident-hmac-acceleration'),
                    after.replace(b'default = []', b'default = ["acceleration"]'),
                    after.replace(b'default-features = false', b'default-features = true'),
                    after.replace(b'"strict-sha2", ', b'')):
        assert changed != after
        assert not hmac.manifest_only(path, before, changed)
    for name, features in hmac.FEATURES.items():
        path = f'crates/{name}/Cargo.toml'
        old = f'[package]\nname="{name}"\nversion="0.1.0"\n[features]\ndefault=[]\n'
        additions = ''.join(f'{key}={json.dumps(value)}\n' for key, value in features.items())
        dependency = ('[dependencies]\nbrynja-mac-hmac={workspace=true' +
                      (',optional=true' if name.endswith('-std') else '') + '}\n') if name in hmac.CONSUMERS else ''
        # Keep an empty dependency table in both projections where relevant.
        before = (old + ('[dependencies]\n' if dependency else '')).encode()
        after = (old + additions + dependency).encode()
        assert hmac.manifest_only(path, before, after)
        assert hmac.manifest_only(path, after, before)
        for mutant in (after.replace(b'default=[]', b'default=["cpu"]'),
                       after.replace(b'version="0.1.0"', b'version="0.1.0"\nbuild="build.rs"'),
                       after.replace(b'[features]', b'[features]\nunrelated=["other"]'),
                       after.replace(b'[package]', b'[profile.release]\nopt-level=0\n[package]')):
            assert not hmac.manifest_only(path, before, mutant)
        for feature in features:
            mutant = after.replace((feature + '=').encode(), (feature + '-extra=').encode())
            assert not hmac.manifest_only(path, before, mutant)
        if dependency:
            for change in (b'workspace=false', b'workspace=true,features=["other"]', b'path="../other"'):
                assert not hmac.manifest_only(path, before, after.replace(b'workspace=true', change))
        assert not hmac.manifest_only(path, None, after)
        assert not hmac.manifest_only(path, before, None)
    before = b'[workspace]\nmembers=["crates/*"]\n[workspace.dependencies]\nother={version="1"}\n'
    after = before + b'brynja-mac-hmac={path="crates/brynja-mac-hmac",version="=0.1.0"}\n'
    assert hmac.workspace_only(before, after)
    assert hmac.workspace_only(after, before)
    for mutant in (after.replace(b'version="1"', b'version="2"'),
                   after.replace(b'version="=0.1.0"', b'version="=0.1.0",features=["other"]'),
                   after.replace(b'path="crates/brynja-mac-hmac"', b'git="https://example.invalid"'),
                   after.replace(b'[workspace]', b'[workspace]\nresolver="2"')):
        assert not hmac.workspace_only(before, mutant)


def source_tests():
    composition_tests()
    hosted_export_tests()
    for path, replacements in hmac.SOURCES.items():
        current = (scope.ROOT / path).read_bytes()
        original = current
        for old, new in replacements:
            assert original.count(new) == 1
            original = original.replace(new, old)
        assert hmac.source_only(path, original, current)
        assert hmac.source_only(path, current, original)
        for mutant in (current + b'fn unrelated() {}\n',
                       current.replace(b'pub ', b'pub(crate) ', 1),
                       current.replace(b'\n', b'\r\n'),
                       current + replacements[0][1]):
            assert mutant != current
            assert not hmac.source_only(path, original, mutant), path
        assert not hmac.source_only(path, None, current)
        assert not hmac.source_only(path, original, None)
    assert scope.select(['crates/brynja-crypto/src/hmac.rs']) == (False, ('hmac',))
    for path in ('hmac.rs', 'hmac_tests.rs'):
        assert scope.select(['crates/brynja-strict/src/' + path]) == (False, ('hmac',))
    for name in ('hmac.rs_extra.rs', 'kmac.rs', 'lib.rs', 'unknown.rs'):
        assert scope.select(['crates/brynja-crypto/src/' + name])[0]


def hosted_export_tests():
    from review_metadata_tests import selected
    path = 'crates/brynja-crypto-cpu-std/src/execution/mod.rs'
    current = (scope.ROOT / path).read_bytes()
    exports = b'#[cfg(feature = "hmac-execution")]\npub use hmac::{HmacError, HmacSelection, PortableHmac};\n'
    legacy = b'#[cfg(feature = "hmac-execution")]\npub use hmac::HmacError;\n'
    assert current.count(exports) == 1
    previous = current.replace(exports, legacy)
    original = current
    for old, new in hmac.SOURCES[path]:
        original = original.replace(new, old)
    for before, after in ((original, current), (previous, current), (original, previous)):
        for left, right in ((before, after), (after, before)):
            assert hmac.source_only(path, left, right)
            assert selected({path: (left, right)}) == (False, ('hmac',))
    for mutant in (current + exports, current + legacy, previous + legacy,
                   current.replace(exports, exports.replace(b'hmac-execution', b'runtime-execution')),
                   current.replace(exports, exports.replace(b'pub use', b'pub(crate) use')),
                   current.replace(exports, exports.replace(b'{HmacError, HmacSelection, PortableHmac}', b'*')),
                   current.replace(exports, exports.replace(b'PortableHmac}', b'PortableHmac, Unknown}')),
                   current + b'pub fn unrelated() {}\n', current.replace(b'\n', b'\r\n')):
        assert mutant != current
        for left, right in ((original, mutant), (mutant, original)):
            assert not hmac.source_only(path, left, right)
            full, groups = selected({path: (left, right)})
            assert full or set(groups) - {'hmac'}, (full, groups)


def composition_tests():
    path, replacements = next(iter(hmac.COMPOSITION.items()))
    current = (scope.ROOT / path).read_bytes()
    original = current
    for old, new in replacements:
        assert original.count(new) == 1
        original = original.replace(new, old)
    assert hmac.source_only(path, original, current)
    assert hmac.source_only(path, current, original)
    for mutant in (current + b'execute()\n', current.replace(b'OwnedSecretRegion', b'WrongOwner', 1),
                   current.replace(b'::drop', b'::wipe', 1), current.replace(b'\n', b'\r\n'),
                   current + replacements[0][1],
                   current.replace(b'hmac_owner_contract.ID', b'"registered.algorithm.sha2"')):
        assert mutant != current
        assert not hmac.source_only(path, original, mutant)
    from review_metadata_tests import selected
    assert selected({path: (original, current)}) == (False, ('hmac',))
    assert 'core' in selected({path: (original, current.replace(b'::drop', b'::wipe', 1))})[1]


def fixture_tests():
    workspace = (scope.ROOT / 'Cargo.lock').read_bytes()
    for name in ('hmac-cleanup', 'hmac-engine-cleanup', 'hmac-execution-cleanup', 'hmac-timing'):
        path = scope.ROOT / 'assurance' / name
        manifest, data = ((path / file).read_bytes() for file in ('Cargo.toml', 'Cargo.lock'))
        inputs.fixture_lock(data, workspace, manifest)
        rejected(lambda: inputs.fixture_lock(data, workspace, manifest.replace(b'publish = false', b'publish = true')))
        rejected(lambda: inputs.fixture_lock(data, workspace, manifest.replace(name.encode(), b'hmac-unknown')))
        rejected(lambda: inputs.fixture_lock(data.replace(b'name = "brynja-core"',
            b'name = "brynja-core"\nchecksum="bad"'), workspace, manifest))


def packaging_tests():
    path, replacements = next(iter(hmac.PACKAGING.items()))
    current = (scope.ROOT / path).read_bytes()
    old, new = replacements[0]
    assert current.count(new) == 1
    original = current.replace(new, old)
    assert hmac.source_only(path, original, current)
    assert hmac.source_only(path, current, original)
    for mutant in (current + b'pass\n', current.replace(b'timeout=600', b'timeout=0'),
                   current.replace(b'brynja-mac-hmac', b'brynja-mac-kmac'),
                   current.replace(b'\n', b'\r\n'), current + new):
        assert mutant != current
        assert not hmac.source_only(path, original, mutant)
    assert not hmac.source_only(path, None, current)
    assert not hmac.source_only(path, original, None)
    with tempfile.TemporaryDirectory(prefix='brynja-hmac-package-scope-') as temporary:
        root = Path(temporary)
        def git(*args):
            return subprocess.check_output(['git', *args], cwd=root, stderr=subprocess.DEVNULL)
        git('init', '-q')
        git('config', 'user.name', 'Scope test')
        git('config', 'user.email', 'scope@example.invalid')
        git('config', 'commit.gpgsign', 'false')
        target = root / path
        target.parent.mkdir(parents=True)
        target.write_bytes(original)
        git('add', '.')
        git('commit', '-qm', 'baseline')
        base = git('rev-parse', 'HEAD').decode().strip()
        target.write_bytes(current)
        assert scope.select_repository(base, root, verified_base=True) == (False, ('hmac',))
        target.write_bytes(current.replace(b'timeout=600', b'timeout=0'))
        # This change to the actual shared runner retains all original owners.
        assert scope.select_repository(base, root, verified_base=True) == scope.select([path])
        assert 'core' in scope.select([path])[1]


def repository_tests():
    # Real dirty Git selection, not a mocked classifier result; no Cargo runs.
    with tempfile.TemporaryDirectory(prefix='brynja-hmac-scope-') as temporary:
        root = Path(temporary)
        def git(*args):
            return subprocess.check_output(['git', *args], cwd=root, stderr=subprocess.DEVNULL)
        def write(path, text):
            file = root / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(text)
        git('init', '-q')
        git('config', 'user.name', 'Scope test')
        git('config', 'user.email', 'scope@example.invalid')
        git('config', 'commit.gpgsign', 'false')
        outer = '[workspace]\nmembers=["crates/*"]\n[workspace.dependencies]\nunrelated={version="1"}\n'
        inner = ('[package]\nname="brynja-crypto"\nversion="0.1.0"\n[features]\ndefault=[]\n'
                 '[dependencies]\nunrelated={workspace=true}\n')
        source = 'crates/brynja-crypto/src/lib.rs'
        write('Cargo.toml', outer)
        write('crates/brynja-crypto/Cargo.toml', inner)
        write(source, '#![no_std]\n')
        git('add', '.')
        git('commit', '-qm', 'baseline')
        base = git('rev-parse', 'HEAD').decode().strip()
        write('Cargo.toml', outer + 'brynja-mac-hmac={path="crates/brynja-mac-hmac",version="=0.1.0"}\n')
        write('crates/brynja-crypto/Cargo.toml', inner + 'brynja-mac-hmac={workspace=true}\n')
        write(source, '#![no_std]\n' + hmac.SOURCES[source][0][1].decode())
        write('crates/brynja-crypto/src/hmac.rs', 'pub use brynja_mac_hmac::Hmac;\n')
        def selected():
            return scope.select_repository(base, root, verified_base=True)
        assert selected() == (False, ('hmac',))
        write(source, (root / source).read_text() + 'pub fn unrelated() {}\n')
        assert selected()[0]
        write(source, '#![no_std]\n' + hmac.SOURCES[source][0][1].decode())
        # A workspace change on another inherited dependency must not borrow
        # the narrow HMAC facade exception, even with unchanged facade manifest.
        write('Cargo.toml', (root / 'Cargo.toml').read_text().replace('version="1"', 'version="2"'))
        assert selected()[0]
        write('Cargo.toml', outer)
        write('crates/brynja-crypto/Cargo.toml', inner)
        write('crates/brynja-hash-sha2/src/lib.rs', 'pub fn changed() {}\n')
        assert selected() == (False, ('sha2', 'hmac'))


def test_hmac_scope():
    graph_tests()
    manifest_tests()
    source_tests()
    fixture_tests()
    packaging_tests()
    repository_tests()
    print('HMAC scope: exact facade/hosted additions, both lock graphs, fixture identities and dirty Git regressions PASS')
