#!/usr/bin/env python3
"""Recheck acceptance metadata after final docs edits; no Rust campaigns."""
from pathlib import Path
import ast
import hashlib
import json
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
for category in ('sha2', 'sha3', 'hash', 'sp800185', 'cryptography'):
    sys.path.insert(0, str(ROOT / 'scripts' / category))

import sha256_public_api
import sha2_public_api
import sha3_public_api
import final_acceptance
import portable_acceptance
import api_profile_model


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


def check_all():
    check_verifier_bindings()
    check_api_metadata()
    # Reuse the exact host-CI validators, including their complete hash checks.
    # Do not call execute_acceptance/run_fixture/package_roots here.
    sha256_public_api.validate_repository(ROOT)
    sha2_public_api.validate_repository(ROOT)
    sha3_public_api.validate_repository(ROOT)
    final_acceptance.validate(ROOT)
    portable_acceptance.validate(ROOT)


if __name__ == '__main__':
    check_all()
    print('Shared verifier bindings, API-profile and all five acceptance metadata/hash closures: PASS (no crypto rerun)')
