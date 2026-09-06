#!/usr/bin/env python3
"""Semantic scope, dirty-tree, deletion and untrusted-baseline regressions."""
import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import miri_scope as scope
import scope_inputs as inputs


def lock(packages):
    lines = ['version = 4']
    for package in packages:
        lines.append('[[package]]')
        lines.extend(f'{k} = {json.dumps(v)}' for k, v in package.items())
    return '\n'.join(lines).encode()


def package(name, dependencies=(), **extra):
    return dict(name=name, version='0.1.0', dependencies=list(dependencies), **extra)


def rejected(call):
    try:
        call()
    except (ValueError, KeyError, TypeError):
        return
    raise AssertionError('accepted ambiguous scope input')


def semantic_tests():
    core = package('brynja-core')
    facade = package('brynja', ['brynja-core'])
    old = lock([core, facade])
    assert inputs.lock_groups(old, lock([core, dict(facade, version='0.24.20')])) == set()
    md5 = package('brynja-legacy-md5', ['brynja-core'])
    assert inputs.lock_groups(old, lock([core, facade, md5])) == {'md5'}
    assert inputs.lock_groups(lock([core, facade, md5]), old) == {'md5'}
    dependency = package('sanitization', source='registry+https://example.invalid', checksum='a')
    adapter = package('brynja-sanitization', ['sanitization'])
    before = lock([dependency, adapter, core, md5])
    after = lock([dict(dependency, version='2.0.4'), adapter, core, md5])
    assert inputs.lock_groups(before, after) == {'sanitization'}
    assert inputs.lock_groups(before, lock([dict(dependency, checksum='b'), adapter, core, md5])) == {'sanitization'}
    sha3 = package('brynja-hash-sha3', ['brynja-core'])
    kmac = package('brynja-mac-kmac', ['brynja-hash-sha3'])
    assert inputs.lock_groups(lock([core, sha3, kmac]), lock([core, dict(sha3, dependencies=[]), kmac])) == {'sha3', 'kmac'}
    for invalid in (None, b'', b'version=3\npackage=[]', lock([core, core]),
                    lock([package('unknown')]), lock([package('brynja-core', ['missing'])]),
                    lock([package('brynja-core', ['other 1.0.0'])])):
        rejected(lambda: inputs.lock_groups(old, invalid))
    rejected(lambda: inputs.lock_groups(lock([dependency]), lock([dict(dependency, checksum='b')])))
    # An unrelated local change cannot hide an external package without a consumer.
    rejected(lambda: inputs.lock_groups(lock([dependency, core]), lock([dict(dependency, checksum='b'), core, md5])))
    assert inputs.version_only(b'[package]\nname="x"\nversion="1"', b'[package]\nname="x"\nversion="2"')
    assert not inputs.version_only(b'[package]\nname="x"', b'[package]\nname="y"')
    a = b'[[tools]]\nid="miri"\nversion="old"\nrevision="a"\n'
    assert inputs.verifier_only(a, a.replace(b'old', b'new'))
    assert not inputs.verifier_only(a, a.replace(b'miri', b'kani'))
    runner = (scope.ROOT / 'scripts/zeroization/check-zeroization-miri.sh').read_bytes()
    assert inputs.runner_groups(runner, runner.replace(b'nightly-2026-09-06', b'nightly-2026-09-07')) == set()
    assert inputs.runner_groups(runner, runner.replace(b'quick_md5() {', b'quick_md5() {\n    # reviewed smoke')) == set()
    assert inputs.runner_groups(runner, runner.replace(b'full_md5() {', b'full_md5() {\n    # reviewed full')) == {'md5'}
    rejected(lambda: inputs.runner_groups(runner, runner.replace(b'run_miri() {', b'run_miri() {\n    false')))
    rejected(lambda: inputs.runner_groups(runner, runner.replace(b'set -euo pipefail', b'set -u')))
    manifest = b'[package]\nname="brynja-legacy-hash-public-api-fixture"\nversion="0.0.0"\npublish=false\n'
    fixture = package('brynja-legacy-hash-public-api-fixture', ['brynja-core'], version_unused='x')
    fixture.pop('version_unused')
    fixture['version'] = '0.0.0'
    inputs.fixture_lock(lock([core, fixture]), old, manifest)
    for altered in (lock([core, fixture, fixture]), lock([dict(core, version='9'), fixture]),
                    lock([core, dict(fixture, dependencies=['missing'])])):
        rejected(lambda: inputs.fixture_lock(altered, old, manifest))
    assert inputs.facade_pin_only(b'x="0.1.0"', b'x="0.2.0"', '0.1.0', '0.2.0')
    assert not inputs.facade_pin_only(b'x="0.1.0"', b'y="0.2.0"', '0.1.0', '0.2.0')
    binding = b'EXPECTED_SHA256 = {"src/lib.rs": "' + b'a' * 64 + b'"}\ncheck()'
    assert inputs.python_bindings_only(binding, binding.replace(b'a' * 64, b'b' * 64))
    assert not inputs.python_bindings_only(binding, binding.replace(b'check()', b'pass'))
    assert not inputs.python_bindings_only(binding, binding.replace(b'src/lib.rs', b'src/other.rs'))
    assert not inputs.python_bindings_only(binding, binding.replace(b'a' * 64, b'b' * 63))
    vector = binding.replace(b'EXPECTED_SHA256', b'TEST_VECTOR')
    assert not inputs.python_bindings_only(vector, vector.replace(b'a' * 64, b'b' * 64))
    digest = b'hash="' + b'a' * 64 + b'"\npath="src/lib.rs"'
    assert inputs.hash_binding_only(digest, digest.replace(b'a' * 64, b'b' * 64))
    assert not inputs.hash_binding_only(digest, digest.replace(b'lib.rs', b'other.rs'))
    assert not inputs.hash_binding_only(digest, digest.replace(b'a' * 64, b'b' * 63))
    assert inputs.matrix_verifier_only(b'[dynamic]\ntoolchain="old"', b'[dynamic]\ntoolchain="new"')
    assert not inputs.matrix_verifier_only(b'[dynamic]\ntoolchain="old"', b'[dynamic]\ncoverage=false')
    for path in ('.cargo/config.toml', 'build.h', 'new_crypto.S', 'rust-toolchain.toml'):
        assert scope.select([path])[0]
    assert scope.select(['assurance/sp800185-final/src/lib.rs'])[1] == ('sha3', 'kmac', 'tuplehash', 'parallelhash')


def git_tests():
    with tempfile.TemporaryDirectory(prefix='brynja-scope-inputs-') as temporary:
        root = Path(temporary)
        def git(*args):
            return subprocess.check_output(['git', *args], cwd=root, stderr=subprocess.DEVNULL)
        git('init', '-q')
        git('config', 'user.name', 'Scope fixture')
        git('config', 'user.email', 'scope@example.invalid')
        git('config', 'commit.gpgsign', 'false')
        source = root / 'crates/brynja-hash-sha3/src/lib.rs'
        source.parent.mkdir(parents=True)
        source.write_text('// baseline\n')
        (root / 'Cargo.lock').write_bytes(lock([package('brynja-core')]))
        git('add', '.')
        git('commit', '-qm', 'baseline')
        git('tag', '-a', 'v0.24.19', '-m', 'unsigned fixture baseline')
        assert scope.select_repository('v0.24.19', root)[0]  # real signature rejection
        real = inputs.git
        def authenticated(path, *args):
            # Only authentication is stubbed; Git diffs and all file reads are real.
            return b'' if args[0] == 'verify-tag' else real(path, *args)
        with patch.object(inputs, 'git', authenticated):
            assert scope.select_repository('v0.24.19', root) == (False, ())
            (root / 'Cargo.lock').write_bytes(b'package="bad"\nversion=4')
            assert scope.select_repository('v0.24.19', root)[0]
            (root / 'Cargo.lock').write_bytes(lock([package('brynja-core')]))
            source.write_text('// dirty sponge\n')
            expected = (False, ('sha3', 'kmac', 'tuplehash', 'parallelhash'))
            assert scope.select_repository('v0.24.19', root) == expected
            git('add', '.')
            assert scope.select_repository('v0.24.19', root) == expected
            source.unlink()
            assert scope.select_repository('v0.24.19', root) == expected
            source.write_text('// baseline\n')
            git('add', '.')
            unknown = root / 'new_crypto.rs'
            unknown.write_text('// untracked production\n')
            assert scope.select_repository('v0.24.19', root)[0]
            unknown.unlink()
            (root / 'Cargo.lock').write_bytes(lock([dict(package('brynja-core'), version='0.9.1')]))
            assert scope.select_repository('v0.24.19', root) == (False, ())
            source.unlink()
            source.symlink_to(root / 'Cargo.lock')
            assert scope.select_repository('v0.24.19', root)[0]
            assert scope.select_repository('--help', root)[0]
            assert scope.select_repository('v9.9.9', root)[0]


if __name__ == '__main__':
    semantic_tests()
    git_tests()
    print('Semantic Miri scope: versions, closures, removals, malformed inputs, dirty/untracked code and baseline failures PASS')
