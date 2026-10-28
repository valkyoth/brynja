"""Reconstruct one sealed pre-publication command-ownership rule as data.

This is only for checking historical recovery records, never for deciding what
the current candidate may reuse. No archived Python is imported or executed.
"""
import shlex

import detached_manifest as records

PATH = 'scripts/release/verification_commands.py'
REVIEWED = '0cc62a35c1a39390d1979170a9d1a9accec759e50052cc72cc2239bc1a039c28'
DRIVERS = frozenset(('scripts/hmac/check-hmac-facade.py',
                     'scripts/hmac/test-hmac-package.py'))


def owners(command, root, current):
    argv = shlex.split(command)
    if (len(argv) != 2 or argv[0] != 'python3' or argv[1] not in DRIVERS
            or current != {'hmac', 'legacy_hmac'}):
        return current
    # The complete old classifier is pinned, not an untrusted declaration of
    # which implementation to exclude. Source seals are checked by History.
    if records.file_hash(root / PATH, 1024 * 1024) != REVIEWED:
        return current
    return {'hmac'}
