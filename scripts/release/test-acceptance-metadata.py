#!/usr/bin/env python3
"""Final metadata checks reject stale docs without launching build campaigns."""
import importlib.util
import copy
import json
import io
import tempfile
import tomllib
from pathlib import Path
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location(
    'acceptance_metadata', Path(__file__).with_name('check-acceptance-metadata.py'))
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)


def package_optional_closure():
    spec = importlib.util.spec_from_file_location('packaged_sha3', metadata.ROOT / 'scripts/sha3/check-sha3-execution.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    class BeforeCargo(Exception):
        pass
    for extras in ((), ('brynja-mac-kmac',), ('brynja-hash-tuple',),
                   ('brynja-hash-parallel', 'brynja-hash-parallel-std')):
        copied = []
        with tempfile.TemporaryDirectory(prefix='brynja-package-inventory-') as directory, \
                patch.object(module, 'PACKAGES', (*module.PACKAGES, *extras)), \
                patch.object(module.shutil, 'copytree', side_effect=lambda source, *_args, **_kw: copied.append(Path(source).name)), \
                patch.object(module, 'run', side_effect=BeforeCargo):
            try:
                module.package(Path(directory), {})
            except BeforeCargo:
                pass
            else:
                raise AssertionError('package inventory did not reach compilation boundary')
        assert len(copied) == len(set(copied)), copied
        assert {'brynja-mac-kmac', 'brynja-hash-tuple', 'brynja-mac-hmac'} <= set(copied)
        for name in copied:
            manifest = tomllib.loads((metadata.ROOT / 'crates' / name / 'Cargo.toml').read_text())
            for dependency in manifest.get('dependencies', {}):
                assert dependency in copied, (name, dependency)
    print('Four package-family inventories retain optional manifest closure without duplicate copies or crypto execution')


def hosted_package_optional_closure():
    spec = importlib.util.spec_from_file_location(
        'packaged_hosted_cpu', metadata.ROOT / 'scripts/cpu/check-hosted-execution.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def check_inventory(packages):
        copied = []
        with tempfile.TemporaryDirectory(prefix='brynja-hosted-inventory-') as directory, \
                patch.object(module, 'PACKAGES', packages), \
                patch.object(module.shutil, 'copytree', side_effect=lambda source, *_args, **_kw: copied.append(Path(source).name)):
            module.isolated(Path(directory))
        assert len(copied) == len(set(copied)), copied
        for name in copied:
            manifest = tomllib.loads((metadata.ROOT / 'crates' / name / 'Cargo.toml').read_text())
            # Cargo resolves optional manifest edges even when their features
            # are disabled. Inspect the actual copied set, not active features.
            for dependency in manifest.get('dependencies', {}):
                assert dependency in copied, (name, dependency)

    check_inventory(module.PACKAGES)
    for missing in ('brynja-mac-kmac', 'brynja-hash-tuple', 'brynja-mac-hmac'):
        try:
            check_inventory(tuple(name for name in module.PACKAGES if name != missing))
        except AssertionError as error:
            assert error.args == ((module.HOST, missing),), error.args
        else:
            raise AssertionError('missing optional hosted dependency escaped: ' + missing)
    print('Hosted package inventory retains optional dependencies and rejects three omission regressions')


def sha2_package_optional_closure():
    spec = importlib.util.spec_from_file_location('packaged_sha2', metadata.ROOT / 'scripts/sha2/check-sha2-execution.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    def check(packages):
        for name in packages:
            manifest = tomllib.loads((metadata.ROOT / 'crates' / name / 'Cargo.toml').read_text())
            for dependency in manifest.get('dependencies', {}):
                assert dependency in packages, (name, dependency)
    check(module.PACKAGES)
    try:
        check(tuple(name for name in module.PACKAGES if name != 'brynja-mac-hmac'))
    except AssertionError as error:
        assert error.args == (('brynja-crypto-cpu-std', 'brynja-mac-hmac'),)
    else:
        raise AssertionError('missing optional HMAC dependency escaped SHA-2 package check')


def public_acceptance_package_closure():
    for module in (metadata.sha256_public_api, metadata.sha2_public_api,
                   metadata.sha3_public_api):
        def check(packages):
            names = {name for name, _version, _required in packages}
            for name in names:
                manifest = tomllib.loads((metadata.ROOT / 'crates' / name / 'Cargo.toml').read_text())
                for dependency in manifest.get('dependencies', {}):
                    assert dependency in names, (name, dependency)
        check(module.PACKAGING_PACKAGES)
        try:
            check(tuple(row for row in module.PACKAGING_PACKAGES if row[0] != 'brynja-mac-hmac'))
        except AssertionError as error:
            assert error.args[0][1] == 'brynja-mac-hmac', error.args
        else:
            raise AssertionError('missing HMAC escaped public acceptance inventory')
    print('Three public package inventories retain optional HMAC and reject its omission')


def legacy_metadata_regressions():
    """The real cheap preflight must catch deltas and enclosing-review drift."""
    policy = metadata.legacy_final_acceptance
    original_read = policy.read
    count = 0
    for family, delta in (('sha1', policy.SHA1_DELTA), ('md5', policy.MD5_DELTA)):
        paths = (policy.MACOS_RESIDENT[family][0],
                 f'crates/brynja-legacy-{family}-std/Cargo.toml',
                 f'crates/brynja-legacy-{family}-std/src/lib.rs')
        original = original_read(metadata.ROOT, delta)
        hashes = tomllib.loads(original)['files']
        for path in paths:
            line = f'"{path}" = "{hashes[path]}"'
            assert original.count(line) == 1
            for mode in ('omitted', 'stale', 'source'):
                def changed_read(root, name):
                    value = original_read(root, name)
                    if name == path and mode == 'source':
                        return value + '\n'
                    if name == delta and mode != 'source':
                        replacement = '' if mode == 'omitted' else f'"{path}" = "' + '0' * 64 + '"'
                        return value.replace(line, replacement)
                    return value
                with patch.object(policy, 'read', side_effect=changed_read):
                    try:
                        metadata.check_all()
                    except ValueError as error:
                        assert ('operational review' in str(error)
                                or 'historical source closure changed' in str(error)), str(error)
                        count += 1
                    else:
                        raise AssertionError(f'legacy {mode} escaped cheap preflight: {path}')
        review = original_read(metadata.ROOT, policy.HASHES)
        source = policy.MACOS_RESIDENT[family][0]
        line = f'"{source}" = "{tomllib.loads(review)["files"][source]}"'
        assert review.count(line) == 1
        for replacement in ('', f'"{source}" = "' + '0' * 64 + '"'):
            def changed_review(root, name):
                value = original_read(root, name)
                return value.replace(line, replacement) if name == policy.HASHES else value
            with patch.object(policy, 'read', side_effect=changed_review):
                try:
                    metadata.check_all()
                except ValueError as error:
                    assert 'final acceptance review binding changed' in str(error), str(error)
                    count += 1
                else:
                    raise AssertionError('legacy enclosing review escaped cheap preflight')
    metadata.check_all()
    print(f'Legacy metadata preflight rejects {count} delta/source/enclosing-review regressions without subprocesses')


def main():
    package_optional_closure()
    sha2_package_optional_closure()
    public_acceptance_package_closure()
    hosted_package_optional_closure()
    with patch('subprocess.run', side_effect=AssertionError('unexpected process')), \
            patch('subprocess.check_call', side_effect=AssertionError('unexpected process')):
        metadata.check_all()
        legacy_metadata_regressions()
        original_read = Path.read_text
        # The hosted review alone previously missed this separate CPU inventory.
        # Reproduce stale pins using the real preflight, with processes forbidden.
        boundary = metadata.cpu_boundary_policy
        boundary_path = metadata.ROOT / boundary.POLICY
        boundary_text = original_read(boundary_path)
        original_open = Path.open
        for source in ('src/lib.rs', 'src/windows_enclave/native/namespace.rs'):
            records = tomllib.loads(boundary_text)['sources']
            record = next(row for row in records if
                          (row['package'], row['path']) == (boundary.DETECTOR, source))
            changed = boundary_text.replace(record['sha256'], '0' * 64)

            def stale_boundary(path, *args, **kwargs):
                return io.BytesIO(changed.encode()) if path == boundary_path else original_open(path, *args, **kwargs)

            with patch.object(Path, 'open', stale_boundary):
                try:
                    metadata.check_all()
                except boundary.CpuBoundaryPolicyError as error:
                    assert 'CPU source changed' in str(error), str(error)
                else:
                    raise AssertionError('stale CPU inventory escaped metadata preflight')
        # Reproduce the gate-only drift that interrupted remote KMAC ASan.
        # Exercise each real validator; no subprocess or Rust work is allowed.
        for policy in (metadata.keccak_hardened_policy, metadata.kmac_execution_policy,
                       metadata.tuplehash_execution_policy):
            review = metadata.ROOT / policy.REVIEW
            for missing in (False, True):
                record = json.loads(original_read(review))
                if missing:
                    del record['sha256']['scripts/tag_gate.sh']
                else:
                    record['sha256']['scripts/tag_gate.sh'] = (
                        '4119e62723bd444b91ca67c45adc7d436f6d88df23940c89e414e46c57d022cf')

                def stale_gate_review(path, *args, **kwargs):
                    return json.dumps(record) if path == review else original_read(path, *args, **kwargs)

                with patch.object(Path, 'read_text', stale_gate_review):
                    try:
                        metadata.check_all()
                    except ValueError as error:
                        assert 'reopen review' in str(error), str(error)
                    else:
                        raise AssertionError('stale or missing shared-gate binding accepted: ' + str(review))
        tag = metadata.ROOT / 'scripts/tag_gate.sh'
        original_gate = original_read(tag)
        for before, after in (
                ('python3 scripts/release/native_sha2_carry_forward.py', 'true'),
                ('python3 scripts/sha2/check-sha2-hardened-native-evidence.py', 'true')):
            changed = original_gate.replace(before, after)
            assert changed != original_gate
            def broken_gate(path, *args, **kwargs):
                return changed if path == tag else original_read(path, *args, **kwargs)
            with patch.object(Path, 'read_text', broken_gate):
                try:
                    metadata.check_all()
                except ValueError as error:
                    assert 'mandatory pre-tag native evidence' in str(error), str(error)
                else:
                    raise AssertionError('native gate bypass escaped metadata preflight')
        hosted = metadata.hosted_acceptance
        for missing in (False, True):
            record = json.loads(original_read(hosted.REVIEW))
            source = 'crates/brynja-crypto-cpu-std/src/windows_enclave/native/namespace.rs'
            if missing:
                del record['sha256'][source]
            else:
                record['sha256'][source] = '0' * 64

            def stale_hosted_read(path, *args, **kwargs):
                return json.dumps(record) if path == hosted.REVIEW else original_read(path, *args, **kwargs)

            with patch.object(Path, 'read_text', stale_hosted_read):
                try:
                    metadata.check_all()
                except ValueError as error:
                    assert str(error) == 'hosted authority changed; reopen review'
                else:
                    raise AssertionError('stale or absent hosted namespace review accepted')
        # Reproduce the compiler-matrix/workflow review drift seen after adding
        # Rust 1.99. Test the actual host validators without starting Cargo.
        for module in (metadata.sha256_public_api, metadata.sha2_public_api, metadata.sha3_public_api):
            for source in (module.RUST_MATRIX, module.WORKFLOW):
                for missing in (False, True):
                    hashes = dict(module.EXPECTED_SHA256)
                    if missing:
                        del hashes[source]
                    else:
                        hashes[source] = '0' * 64
                    with patch.object(module, 'EXPECTED_SHA256', hashes):
                        try:
                            module.validate_repository(metadata.ROOT)
                        except module.AcceptancePolicyError:
                            pass
                        else:
                            raise AssertionError('compiler/CI review drift accepted')
        parallel = metadata.parallelhash_policy
        for missing in (False, True):
            hashes = dict(parallel.HASHES)
            fixture = Path('assurance/parallelhash-public-api/Cargo.toml')
            if missing:
                del hashes[fixture]
            else:
                hashes[fixture] = 'e22082db08e6154420d2d6fc05267e844dc1d767c6c7cd3922e464efe00ad724'
            with patch.object(parallel, 'HASHES', hashes):
                try:
                    metadata.check_all()
                except parallel.ParallelHashPolicyError:
                    pass
                else:
                    raise AssertionError('stale or missing ParallelHash facade-fixture binding accepted')
        # Reproduce the actual pre-rustdoc MD5 pin that escaped the local-family
        # checks but failed the cross-family acceleration review in GitHub.
        contract = metadata.acceleration_availability
        original_contract_read = contract.read
        for missing in (False, True):
            document = json.loads(original_contract_read(metadata.ROOT, contract.REVIEW))
            source = 'crates/brynja-legacy-md5/src/batch/execution.rs'
            if missing:
                del document['sha256'][source]
            else:
                document['sha256'][source] = 'f3dd8c62c846520fd6b30045dd9525229c7775974470a9432b3a7ff94aa7729a'

            def stale_acceleration_read(root, name):
                if name == contract.REVIEW:
                    return json.dumps(document).encode()
                return original_contract_read(root, name)

            with patch.object(contract, 'read', side_effect=stale_acceleration_read):
                try:
                    metadata.check_all()
                except ValueError as error:
                    assert 'availability contract/source closure changed' in str(error)
                else:
                    raise AssertionError('stale or missing cross-family acceleration binding accepted')
        # Reproduce the stale shared package-helper pin seen in CI, in each
        # consuming MD5 review. Exercise the real validators, not mocked passes.
        original_read = Path.read_text
        source = 'scripts/md5/check-md5-package.py'
        for review, key in (
            ('scripts/md5/md5-reviewed.toml', 'sha256'),
            ('scripts/md5/md5-cpu-reviewed.toml', 'files'),
            ('scripts/md5/execution-reviewed.json', 'sha256'),
            ('scripts/md5/hardened-reviewed.json', 'sha256'),
        ):
            for missing in (False, True):
                hashes = dict(metadata.verifier_review(review, key))
                if missing:
                    del hashes[source]
                else:
                    hashes[source] = '0' * 64
                if review.endswith('.json'):
                    broken = json.dumps({'schema': 1, key: hashes})
                else:
                    broken = '[' + key + ']\n' + ''.join(
                        f'"{name}" = "{value}"\n' for name, value in hashes.items())

                def altered_read(path, *args, **kwargs):
                    if path == metadata.ROOT / review:
                        return broken
                    return original_read(path, *args, **kwargs)

                # Operational JSON uses read_bytes; keep both real read paths
                # covered without mutating the actual checkout.
                original_bytes = Path.read_bytes

                def altered_bytes(path):
                    if path == metadata.ROOT / review:
                        return broken.encode()
                    return original_bytes(path)

                with patch.object(Path, 'read_text', altered_read), \
                        patch.object(Path, 'read_bytes', altered_bytes):
                    try:
                        metadata.check_all()
                    except ValueError as error:
                        assert any(message in str(error) for message in (
                            'MD5 reviewed', 'CPU hash', 'CPU source changed',
                            'MD5 execution reviewed', 'hardened source review changed')), str(error)
                    else:
                        raise AssertionError('stale or missing MD5 package binding accepted')
        read_review = metadata.verifier_review
        for review, key in metadata.VERIFIER_REVIEWS:
            for script in metadata.VERIFIERS:
                for missing in (False, True):
                    hashes = dict(read_review(review, key))
                    if missing:
                        del hashes[script]
                    else:
                        hashes[script] = '0' * 64

                    def altered(path, selected_key):
                        return hashes if path == review else read_review(path, selected_key)

                    with patch.object(metadata, 'verifier_review', side_effect=altered):
                        try:
                            metadata.check_all()
                        except ValueError as error:
                            assert 'verifier review hash drift' in str(error)
                            assert review in str(error) and script in str(error)
                        else:
                            raise AssertionError('missing or stale verifier binding accepted')
        model = metadata.api_profile_model
        for reader, mutate in (
            ('read_policy', lambda value: value['schema'].update(surface_register_sha256='0' * 64)),
            ('read_surfaces', lambda value: value.update(policy_sha256='0' * 64)),
        ):
            value = copy.deepcopy(getattr(model, reader)())
            mutate(value)
            with patch.object(model, reader, return_value=value):
                try:
                    metadata.check_all()
                except model.ProfileError as error:
                    assert 'reopen review' in str(error)
                else:
                    raise AssertionError('stale API surface binding accepted')
        for name in ('REGISTER', 'COVERAGE'):
            for exists in (True, False):
                stale = Mock(name='stale metadata')
                stale.is_file.return_value = exists
                stale.read_bytes.return_value = b'stale'
                with patch.object(model, name, stale):
                    try:
                        metadata.check_all()
                    except model.ProfileError as error:
                        assert 'API-profile metadata is stale' in str(error)
                    else:
                        raise AssertionError('missing or stale API metadata accepted')
        for module, path in (
            (metadata.sha2_public_api, metadata.sha2_public_api.LEAF_README),
            (metadata.sha2_public_api, metadata.sha2_public_api.FACADE_README),
            (metadata.sha3_public_api, metadata.sha3_public_api.FACADE_README),
        ):
            with patch.dict(module.EXPECTED_SHA256, {path: '0' * 64}):
                try:
                    metadata.check_all()
                except module.AcceptancePolicyError as error:
                    assert 'hash drift' in str(error)
                else:
                    raise AssertionError('stale README accepted')
        for module in (metadata.final_acceptance, metadata.portable_acceptance):
            hashes = module.expected_hashes(metadata.ROOT)
            hashes['README.md'] = '0' * 64
            with patch.object(module, 'expected_hashes', return_value=hashes):
                try:
                    metadata.check_all()
                except RuntimeError as error:
                    assert 'hash drift' in str(error)
                else:
                    raise AssertionError('stale root README accepted')
    gate = (metadata.ROOT / 'scripts/release/validate-release-metadata.sh').read_text()
    for name in ('check', 'test'):
        assert '\npython3 scripts/release/' + name + '-acceptance-metadata.py\n' in gate
    print('Final metadata rejects five stale README bindings and six API-profile regressions without crypto execution')
    print('Shared verifier preflight rejects 28 stale or missing review bindings without crypto execution')
    print('Final metadata rejects eight stale/missing MD5 package-helper bindings without crypto execution')
    print('Final metadata rejects the stale MD5 rustdoc acceleration pin and missing binding without crypto execution')
    print('Final metadata rejects stale/missing ParallelHash facade-fixture bindings without crypto execution')
    print('Final metadata rejects strict/fallback native-gate bypasses without crypto execution')
    print('Final metadata rejects six stale/missing Keccak, KMAC and TupleHash gate bindings without crypto execution')


if __name__ == '__main__':
    main()
