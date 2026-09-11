#!/usr/bin/env python3
"""Recheck acceptance metadata after final docs edits; no Rust campaigns."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
for category in ('sha2', 'sha3', 'hash', 'sp800185', 'cryptography'):
    sys.path.insert(0, str(ROOT / 'scripts' / category))

import sha256_public_api
import sha2_public_api
import sha3_public_api
import final_acceptance
import portable_acceptance
import api_profile_model


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
    print('API-profile and all five acceptance metadata/hash closures: PASS (no crypto rerun)')
