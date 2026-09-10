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
    assert b'nightly-2026-09-10' in runner
    assert inputs.runner_groups(runner, runner.replace(b'nightly-2026-09-10', b'nightly-2026-09-10')) == set()
    assert inputs.runner_groups(runner, runner.replace(b'quick_md5() {', b'quick_md5() {\n    # reviewed smoke')) == set()
    assert inputs.runner_groups(runner, runner.replace(b'full_md5() {', b'full_md5() {\n    # reviewed full')) == {'md5'}
    # Adding the registered model leaves all existing full campaign bodies intact.
    start = runner.index(b'quick_acceleration() {')
    end = runner.index(b'quick_static_cpu()', start)
    previous = (runner[:start] + runner[end:]).replace(b'legacy acceleration static_cpu)', b'legacy static_cpu)')
    assert inputs.runner_groups(previous, runner) == {'acceleration'}
    rejected(lambda: inputs.runner_groups(runner, previous))
    rejected(lambda: inputs.runner_groups(runner, runner.replace(b'run_miri() {', b'run_miri() {\n    false')))
    rejected(lambda: inputs.runner_groups(runner, runner.replace(b'set -euo pipefail', b'set -u')))
    manifest = b'[package]\nname="brynja-legacy-hash-public-api-fixture"\nversion="0.0.0"\npublish=false\n'
    fixture = package('brynja-legacy-hash-public-api-fixture', ['brynja-core'], version_unused='x')
    fixture.pop('version_unused')
    fixture['version'] = '0.0.0'
    inputs.fixture_lock(lock([core, fixture]), old, manifest)
    nested_name = 'brynja-legacy-hash-public-api-fixture'
    nested = package(nested_name, ['brynja-core'])
    nested_manifest = ('[package]\nname="' + nested_name + '"\nversion="0.1.0"\npublish=false\n').encode()
    outer = dict(fixture, name='brynja-legacy-hash-final-fixture', dependencies=[nested_name])
    outer_manifest = manifest.replace(b'public-api-fixture', b'final-fixture')
    nested_lock = lock([core, nested])
    inputs.fixture_lock(lock([core, nested, outer]), old, outer_manifest, (nested_lock, nested_manifest))
    rejected(lambda: inputs.fixture_lock(lock([core, nested, outer]), old, outer_manifest))
    rejected(lambda: inputs.fixture_lock(lock([core, nested, outer]), old, outer_manifest,
        (lock([dict(core, version='9'), nested]), nested_manifest)))
    rejected(lambda: inputs.fixture_lock(lock([core, nested, outer]), old, outer_manifest,
        (lock([core, nested, nested]), nested_manifest)))
    rejected(lambda: inputs.fixture_lock(lock([core, nested, outer]), old, outer_manifest,
        (lock([core, dict(nested, dependencies=['missing'])]), nested_manifest)))
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
        reviewed = root / 'scripts/sha1/reviewed.toml'
        reviewed.parent.mkdir(parents=True)
        digest = '[files]\n"README.md"="' + 'a' * 64 + '"\n'
        reviewed.write_text(digest)
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
            contract = root / 'assurance/acceleration-contract'
            contract.mkdir(parents=True)
            manifest = (scope.ROOT / 'assurance/acceleration-contract/Cargo.toml').read_bytes()
            model_lock = (scope.ROOT / 'assurance/acceleration-contract/Cargo.lock').read_bytes()
            (contract / 'Cargo.toml').write_bytes(manifest)
            (contract / 'Cargo.lock').write_bytes(model_lock)
            model_source = contract / 'src/lib.rs'
            model_source.parent.mkdir()
            model_source.write_text('// new isolated model\n')
            assert scope.select_repository('v0.24.19', root) == (False, ('acceleration',))
            for table in ('dependencies', 'dev-dependencies', 'build-dependencies',
                          'target.x86_64-unknown-linux-gnu.dependencies'):
                (contract / 'Cargo.toml').write_bytes(manifest + f'\n[{table}]\nunknown="1"\n'.encode())
                assert scope.select_repository('v0.24.19', root)[0]
            (contract / 'Cargo.toml').write_bytes(manifest)
            for bad in (b'version=3\npackage=[]', model_lock + b'\n[[package]]\nname="unknown"\nversion="1"',
                        model_lock.replace(b'0.0.0', b'9.0.0')):
                (contract / 'Cargo.lock').write_bytes(bad)
                assert scope.select_repository('v0.24.19', root)[0]
            (contract / 'Cargo.lock').unlink()
            assert scope.select_repository('v0.24.19', root)[0]
            (contract / 'Cargo.toml').unlink()
            model_source.unlink()
            reviewed.write_text(digest.replace('a' * 64, 'b' * 64))
            assert scope.select_repository('v0.24.19', root) == (False, ())
            reviewed.write_text(digest.replace('README.md', 'src/lib.rs'))
            assert scope.select_repository('v0.24.19', root) == (False, ('sha1', 'legacy'))
            reviewed.write_text(digest.replace('a' * 64, 'a' * 63))
            assert scope.select_repository('v0.24.19', root) == (False, ('sha1', 'legacy'))
            reviewed.write_text(digest)
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


def mir_span_tests():
    raw = (scope.ROOT / 'scripts/cryptography/api_profile_contracts.py').read_bytes()
    moved = raw.replace(b'owner.rs:83:1: 83:32', b'owner.rs:78:1: 78:32')
    assert moved != raw
    assert inputs.mir_spans_only(raw, moved)
    assert inputs.mir_spans_only(moved, raw)
    for bad in (None, raw.replace(b'REGISTERED_CALLER_MIR_HEADERS =', b'OTHER ='),
                raw.replace(b'owner.rs:83', b'other.rs:83'),
                raw.replace(b'drop(_1: &mut HardenedSha2Owner)', b'drop(_1: &mut OtherOwner)'),
                raw.replace(b'HardenedSha2Owner::wipe(', b'HardenedSha2Owner::skip('),
                raw.replace(b'output_staging:secret-derived', b'output_staging:public'),
                raw + b'\nperform_extra_work()\n',
                raw + b'\nREGISTERED_CALLER_MIR_HEADERS = {}\n'):
        assert not inputs.mir_spans_only(raw, bad)
    # End-to-end repository selection, including malformed and removed inputs.
    path = 'scripts/cryptography/api_profile_contracts.py'
    def git(_root, *args):
        return path.encode() if args[0] == 'diff' else b''
    def selected(after):
        with patch.object(inputs, 'git', side_effect=git), patch.object(
                inputs, 'snapshot', side_effect=lambda r, b, p: (raw, after) if p == path else (None, None)):
            return scope.select_repository('v0.24.33')
    assert selected(moved) == (False, ())
    for bad in (None, raw + b'\nperform_extra_work()\n'):
        full, groups = selected(bad)
        assert 'core' in groups and 'md5' in groups and 'sha3' in groups
    assert selected(b'broken Python =')[0]


def contract_tests():
    manifest = (scope.ROOT / 'assurance/acceleration-contract/Cargo.toml').read_bytes()
    model_lock = (scope.ROOT / 'assurance/acceleration-contract/Cargo.lock').read_bytes()
    inputs.isolated_contract(model_lock, manifest)
    for before, after in ((None, manifest), (model_lock, None),
                          (model_lock, manifest.replace(b'publish = false', b'publish = true')),
                          (model_lock, manifest.replace(b'0.0.0', b'1.0.0'))):
        rejected(lambda: inputs.isolated_contract(before, after))
    assert inputs.lock_groups(model_lock, model_lock.replace(b'0.0.0', b'0.0.1')) == set()
    # An unknown fixture path still fails closed even when its lock is valid.
    assert scope.select(['assurance/unknown/Cargo.toml'])[0]
    assert scope.select(['assurance/unknown/src/lib.rs'])[0]


if __name__ == '__main__':
    semantic_tests()
    git_tests()
    contract_tests()
    mir_span_tests()
    print('Semantic Miri scope: versions, closures, removals, malformed inputs, dirty/untracked code and baseline failures PASS')
