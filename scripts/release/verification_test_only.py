"""Source-bound isolated test corrections, not a test-directory exemption.

These exact reviewed revisions change mutation construction and its regression
only. Neither program is a shared implementation/checker helper. The quick
verifier imports the normalization test, so it must rerun for either change.
Unknown revisions, shared helpers, source/build changes and metadata policy
changes retain normal family invalidation. Digests bind review, not authority.
"""
import hashlib
import subprocess

import verification_plan as plans

NORMALIZATION = 'scripts/legacy-hmac/test-legacy-hmac-md5-normalization.py'
VERIFICATION = 'scripts/legacy-hmac/test-legacy-hmac-verification.py'
REVISIONS = {
    NORMALIZATION: ('f52c7358d177ee7867c19ae74f38d40741404b732208496367feb1b8faeae4d8',
                    '0513085e90465bc5311b511d23a9e750e4b2e733c3ef127ac27f24dae8c8c945'),
    VERIFICATION: ('aa365c992967d3e691796b14eed499cbdf72baba7e26c979d1f58a13b0107856',
                   'c01068bcc8ed438c046299fd54b8586aecbe1e1034ef762090898cd6ff1ee71b'),
}
DEPENDENTS = {NORMALIZATION: {NORMALIZATION, VERIFICATION}, VERIFICATION: {VERIFICATION}}
TOML_BINDINGS = {'security/cryptographic-api-profile-policy.toml',
                 'scripts/hash/final-acceptance-hashes.toml'}
JSON_BINDINGS = {'security/cryptographic-api-profile-register.json', 'assurance/evidence.json'}


def prove(root, base, changed):
    """Called only after validating an ancestor's execution evidence.

Return the exact drivers which must execute now, or no exception. Recompute
the delta and read raw historical/current bytes, not a claimed path list from
the old receipt. Current baseline checks and all approval/tool checks remain
outside this exception and are never skipped by it.
"""
    try:
        if set(changed) != set(plans.changed_paths(root, base)):
            return None
        corrected = set(changed) & REVISIONS.keys()
        if not corrected:
            return None
        for path in changed:
            before, after = plans.inputs.snapshot(root, base, path)
            if path in REVISIONS:
                if (before is None or after is None or
                        tuple(hashlib.sha256(raw).hexdigest() for raw in (before, after)) != REVISIONS[path]):
                    return None
            elif path in TOML_BINDINGS:
                if before is None or after is None or not plans.inputs.hash_binding_only(before, after):
                    return None
            elif path in JSON_BINDINGS:
                if before is None or after is None or not plans.inputs.json_hash_binding_only(before, after):
                    return None
            elif path.startswith('scripts/release/') and path.endswith('.py'):
                # Already mandatory current orchestration checks, not a new
                # runtime exemption. Changed command drivers still rerun.
                continue
            elif path.endswith('.md') and path.startswith(('docs/', 'security/pentest/')):
                continue
            else:
                return None
        return set().union(*(DEPENDENTS[path] for path in corrected))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return None
