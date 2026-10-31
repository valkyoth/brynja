"""Exact v0.25.2 checker corrections; never a general test-file exemption.

The profile binds reviewed bytes, not approval. Call only after validating a
historical receipt. It can preserve Miri/ASan/Kani/matrix observations, never
repository checks or native approval. Verifier changes require independent
review just like the surrounding carry-forward implementation.
"""
import hashlib
import json
import subprocess

import verification_plan as plans
from verification_tooling_review import REVIEW, FOLLOWUP

PHASES = frozenset({'miri', 'asan', 'kani', 'matrix'})
SECURITY_METADATA = frozenset('security/' + name for name in (
    'cryptographic-api-profile-policy.toml', 'cryptographic-api-profile-register.json',
    'hosted-cpu-execution-reviewed.json', 'sha2-hardened-execution-reviewed.json'))
# Trusted orchestration, exercised by the mandatory current repository suite.
# Do not extend this to a directory glob or to any execution/test driver.
ORCHESTRATION = frozenset('scripts/release/' + name for name in (
    'verification_tooling_reuse.py', 'verification_tooling_review.py',
    'verification_tooling_tests.py', 'verification_carry_forward.py',
    'test-detached-verification.py'))
GENERATED = 'assurance/evidence.json'
NATIVE_REVIEW = 'security/native-reuse/evidence-approval.json'
# Owner approved this exact metadata transition on 2026-10-30. These hashes
# cannot authorize native reuse: the independently supplied protected pin and
# every original artifact are still checked by native_evidence_approval.
NATIVE_PAIR = ('367046bb0dd112d0be1e5aed37218883a3469b1bde3c64bc025ce03eb015dca8',
               '913a2f47caf84000f61671c7643f12824642057e3ae9f142b92213ba3a4b7f6d')
ADDED_INPUTS = frozenset({
    'scripts/assurance/assurance_kani_tests.py',
    'scripts/release/verification_tooling_reuse.py',
    'scripts/release/verification_tooling_review.py',
    'scripts/release/verification_tooling_tests.py',
})


def approved_native_update(root, before, after):
    """Recognize one approved metadata change; never supply its trusted pin."""
    if before is None or after is None or tuple(
            hashlib.sha256(raw).hexdigest() for raw in (before, after)) != NATIVE_PAIR:
        return False
    import native_evidence_approval as approval
    head = plans.inputs.git(root, 'rev-parse', 'HEAD').decode().strip()
    for family in approval.INDEXES:
        approval.validate(family, root, head)
    return True


def generated_only(root, base, before, after, changed):
    """Preserve tool/target/claim metadata and bind every updated input hash."""
    old, new = json.loads(before), json.loads(after)
    left, right = old.pop('inputs'), new.pop('inputs')
    if old != new or not set(left) <= set(right) or not set(right) - set(left) <= ADDED_INPUTS:
        return False
    for name in set(left) | set(right):
        if left.get(name) == right.get(name):
            continue
        previous, current = plans.inputs.snapshot(root, base, name)
        if (current is None or right[name] != hashlib.sha256(current).hexdigest()
                or (name not in changed and previous != current)):
            return False
    return True


def review():
    value = REVIEW
    if (set(value) != {'schema', 'bases', 'files', 'generated_before'} or type(value['schema']) is not int
            or value['schema'] != 1 or not isinstance(value['bases'], dict)
            or not isinstance(value['files'], dict)):
        raise ValueError('invalid tooling review')
    return value


def prove(root, base, changed):
    """Return eligible phases only for the complete exact reviewed delta.

No receipt/command/tool checks are replaced here. In particular a historical
Kani-driver correction is allowed only across the Miri snapshot: the refreshed
ASan/Kani snapshot already contains it. Unknown baselines have no exception.
"""
    try:
        policy = review()
        phases = policy['bases'].get(base, [])
        if not phases or not set(phases) <= PHASES:
            return set()
        if set(changed) != set(plans.changed_paths(root, base)):
            return set()
        corrected = False
        for name in changed:
            before, after = plans.inputs.snapshot(root, base, name)
            if name in ORCHESTRATION:
                # snapshot still rejects symlinks/oversized inputs.
                if after is None:
                    return set()
                continue
            if name == NATIVE_REVIEW:
                if not approved_native_update(root, before, after):
                    return set()
                continue
            if name == GENERATED:
                # The original generated inventory had three stale hashes for
                # unchanged orchestration. Bind that exact old document; the
                # current document must bind actual bytes, never those stale hashes.
                if (before is None or after is None
                        or hashlib.sha256(before).hexdigest() not in policy['generated_before']
                        or not generated_only(root, base, before, after, changed)):
                    return set()
                continue
            documentation = (name == 'README.md' or name.startswith('crates/') and
                             name.endswith('/README.md') or
                             name.startswith(('release-notes/', 'security/pentest/')) and name.endswith('.md'))
            if (not (name.startswith(('scripts/', 'docs/')) or name in SECURITY_METADATA or documentation)
                    # Only this scope classifier may use an exact reviewed
                    # byte pair. Miri task definitions/execution stay excluded.
                    or (name.startswith('scripts/zeroization/')
                        and name != 'scripts/zeroization/scope_hmac.py')
                    or (name == 'scripts/assurance/check-kani.sh' and 'kani' in phases)):
                return set()
            # The original review stays immutable. The follow-up lists exact
            # README/report bytes, pin-only changes and publisher/test fixes;
            # it does not exempt arbitrary documentation or repository scripts.
            row = FOLLOWUP.get(name, policy['files'].get(name))
            if not row or after is None:
                return set()
            old = hashlib.sha256(before).hexdigest() if before is not None else None
            if old not in row['before'] or hashlib.sha256(after).hexdigest() != row['after']:
                return set()
            # Permission changes and symlink substitutions are not byte-only fixes.
            previous = plans.inputs.git(root, 'ls-tree', base, '--', name)
            mode = '100755' if (root / name).stat().st_mode & 0o111 else '100644'
            if mode != row['mode'] or (previous and previous.split()[0].decode() != mode):
                return set()
            corrected = True
        return set(phases) if corrected else set()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return set()
