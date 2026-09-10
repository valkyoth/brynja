#!/usr/bin/env python3
"""Recheck acceptance metadata after final docs edits; no Rust campaigns."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
for category in ('sha2', 'sha3', 'hash', 'sp800185'):
    sys.path.insert(0, str(ROOT / 'scripts' / category))

import sha256_public_api
import sha2_public_api
import sha3_public_api
import final_acceptance
import portable_acceptance


def check_all():
    # Reuse the exact host-CI validators, including their complete hash checks.
    # Do not call execute_acceptance/run_fixture/package_roots here.
    sha256_public_api.validate_repository(ROOT)
    sha2_public_api.validate_repository(ROOT)
    sha3_public_api.validate_repository(ROOT)
    final_acceptance.validate(ROOT)
    portable_acceptance.validate(ROOT)


if __name__ == '__main__':
    check_all()
    print('All five acceptance metadata/hash closures: PASS (no crypto rerun)')
