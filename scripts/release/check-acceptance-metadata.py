#!/usr/bin/env python3
"""Recheck acceptance metadata after final docs edits; no Rust campaigns."""
from pathlib import Path
import ast
import hashlib
import importlib.util
import json
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
for category in ('sha2', 'sha3', 'hash', 'sp800185', 'cryptography', 'md5', 'cpu', 'parallelhash', 'kmac', 'tuplehash', 'legacy-hash'):
    sys.path.insert(0, str(ROOT / 'scripts' / category))

import sha256_public_api
import sha256_policy
import sha2_hardened_execution_policy
import sha256_batch_policy
import sha512_batch_policy
import keccak_batch_policy
import sha2_public_api
import sha3_public_api
import final_acceptance
import portable_acceptance
import execution_acceptance
import api_profile_model
import md5_policy
import md5_cpu_policy
import md5_execution_policy
import md5_hardened_policy
import acceleration_availability
import cpu_boundary_policy
import parallelhash_policy
import tuplehash_policy
import keccak_hardened_policy
import kmac_execution_policy
import tuplehash_execution_policy
import legacy_final_acceptance

_hosted_spec = importlib.util.spec_from_file_location(
    'hosted_acceptance', ROOT / 'scripts/cpu/check-hosted-execution.py')
hosted_acceptance = importlib.util.module_from_spec(_hosted_spec)
_hosted_spec.loader.exec_module(hosted_acceptance)

_static_spec = importlib.util.spec_from_file_location(
    'static_acceptance', ROOT / 'scripts/cpu/check-static-execution.py')
static_acceptance = importlib.util.module_from_spec(_static_spec)
_static_spec.loader.exec_module(static_acceptance)


VERIFIER_REVIEWS = (
    ('scripts/sha2/sha2_reviewed_hashes.py', 'TEST_HASHES'),
    ('scripts/sha2/sha2-execution-reviewed.toml', 'files'),
    ('scripts/sha3/sha3-execution-reviewed.toml', 'files'),
    ('scripts/legacy-hash/final-reviewed.toml', 'files'),
    ('security/tuplehash-execution-reviewed.json', 'sha256'),
    ('security/kmac-execution-reviewed.json', 'sha256'),
    ('security/keccak-hardened-reviewed.json', 'sha256'),
)
VERIFIERS = ('scripts/zeroization/check-zeroization-miri.sh',
             'scripts/zeroization/check-zeroization-sanitizer.sh')


def verifier_review(path, key):
    text = (ROOT / path).read_text(encoding='utf-8')
    if path.endswith('.py'):
        values = [ast.literal_eval(node.value) for node in ast.parse(text).body
                  if isinstance(node, ast.Assign) and any(
                      isinstance(target, ast.Name) and target.id == key
                      for target in node.targets)]
        if len(values) != 1:
            raise ValueError('ambiguous verifier review: ' + path)
        return values[0]
    document = json.loads(text) if path.endswith('.json') else tomllib.loads(text)
    return document[key]


def check_verifier_bindings():
    for path, key in VERIFIER_REVIEWS:
        hashes = verifier_review(path, key)
        for script in VERIFIERS:
            actual = hashlib.sha256((ROOT / script).read_bytes().replace(b'\r\n', b'\n')).hexdigest()
            if hashes.get(script) != actual:
                raise ValueError(f'verifier review hash drift: {path}: {script}')


def check_api_metadata():
    # A standards refresh invalidates this downstream binding even when no
    # implemented API changed. Check both generated outputs without compilation.
    register = api_profile_model.build_register(
        api_profile_model.read_policy(), api_profile_model.read_surfaces())
    for path, expected in (
        (api_profile_model.REGISTER, api_profile_model.json_bytes(register)),
        (api_profile_model.COVERAGE, api_profile_model.render_coverage(register)),
    ):
        if not path.is_file() or path.read_bytes() != expected:
            api_profile_model.fail(f'API-profile metadata is stale: {path.name}')


def check_current_fixture_versions():
    """Current facade consumers must resolve the checkout, not the previous tag."""
    version = tomllib.loads((ROOT / 'crates/brynja/Cargo.toml').read_text())['package']['version']
    for fixture in ('sha2-public-api', 'sha3-public-api', 'cshake-public-api',
                    'sp800185-public-api', 'tuplehash-public-api', 'parallelhash-public-api',
                    'hash-final-acceptance', 'sp800185-final', 'kmac-public-api'):
        base = ROOT / 'assurance' / fixture
        dependency = tomllib.loads((base / 'Cargo.toml').read_text())['dependencies'].get('brynja')
        expected = (None if fixture in ('hash-final-acceptance', 'sp800185-final') else
                    {'path': '../../crates/brynja', 'version': '=' + version, 'default-features': False})
        if fixture == 'kmac-public-api':
            expected = {'path': '../../crates/brynja'}
        locked = [package for package in tomllib.loads((base / 'Cargo.lock').read_text())['package']
                  if package['name'] == 'brynja']
        if (dependency != expected
                or len(locked) != 1 or locked[0]['version'] != version or 'source' in locked[0]):
            raise ValueError('current facade fixture version/source mismatch: ' + fixture)


def check_all():
    check_current_fixture_versions()
    # This independent closure also binds the shared check/Miri/sanitizer
    # drivers. Reuse its exact CI validator, never its Cargo/package campaign.
    static_acceptance.validate()
    check_verifier_bindings()
    # The public-API review does not include this separate portable facade
    # dependency inventory. Run the exact source/manifest validator used by CI.
    sha256_policy.validate(ROOT)
    # Validate the complete legacy source/delta inventory, not just its two
    # shared verifier pins. This is metadata only; never run its Cargo driver.
    legacy_final_acceptance.validate(ROOT)
    check_api_metadata()
    # Include the real mandatory native-gate structure check; a stale policy
    # assertion must fail this cheap preflight rather than only remote CI.
    sha2_hardened_execution_policy.validate(ROOT)
    # These validators bind the entire shared gate, not only verifier scripts.
    # Catch stale review pins here before starting a detached sanitizer phase.
    for policy in (keccak_hardened_policy, kmac_execution_policy, tuplehash_execution_policy):
        policy.validate(ROOT)
    # Same metadata-only validator used in CI, including newly added native
    # source modules. This does not execute the hosted package/test campaigns.
    hosted_acceptance.validate()
    cpu_boundary_policy.validate(ROOT)
    # Reuse the exact host-CI validators, including their complete hash checks.
    # Do not call execute_acceptance/run_fixture/package_roots here.
    sha256_public_api.validate_repository(ROOT)
    sha256_batch_policy.validate(ROOT)
    sha512_batch_policy.validate(ROOT)
    keccak_batch_policy.validate(ROOT)
    sha2_public_api.validate_repository(ROOT)
    sha3_public_api.validate_repository(ROOT)
    final_acceptance.validate(ROOT)
    portable_acceptance.validate(ROOT)
    execution_acceptance.validate(ROOT)
    # These share packaging helpers. Recheck all four review closures after
    # final packaging/docs edits, without invoking their Rust test drivers.
    md5_policy.validate(ROOT)
    md5_cpu_policy.validate(ROOT)
    md5_execution_policy.validate(ROOT)
    md5_hardened_policy.validate(ROOT)
    # The cross-family acceleration inventory also binds MD5 source comments.
    # Check its full current closure, not only each family's local review.
    acceleration_availability.validate(ROOT)
    # Its facade fixture pin participates in historical native carry-forward.
    parallelhash_policy.validate(ROOT)
    tuplehash_policy.validate(ROOT)


if __name__ == '__main__':
    check_all()
    print('Shared verifier bindings, static CPU, API-profile, six acceptance, four MD5, acceleration and ParallelHash metadata/hash closures: PASS (no crypto rerun)')
