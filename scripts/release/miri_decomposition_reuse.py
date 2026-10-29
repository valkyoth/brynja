"""Exact reviewed task-decomposition delta, not a general runner exemption.

For families whose implementation inputs did not change, the 2026-10-29 runner
adds only width selection/coverage reporting; old selectors keep their meaning.
The two catalog changes are handled by snapshot-relative task comparison. Rust
test edits still invalidate their families. Pins bind this review, not authority.
"""
import hashlib
import os
import subprocess

import verification_plan as plans
import miri_dependencies

REVISIONS = {
    'scripts/zeroization/miri_cases.py': (
        '1c7d01c4937aed4966a6166ca888799d954da8b2c39dfc00a6e61a85c392a6b1',
        'd6c5a469cdd29cd2a66630747cbf1dca75549e9b1245dd769b1b83a4a223a8d0'),
    'scripts/zeroization/miri_tasks.py': (
        'c16a13f7b6f5ff864254eef185f4fcb0c4184a533e3df699849dc6945a92e25c',
        '9d5e9baafcc5fa75215af8a37a666a8910813aa02bc5d071c69ddb28b9ff60e3'),
    'scripts/zeroization/run-miri-task.py': (
        '28fc766082045e4f5d1524bf83ffc5eb66c9c1b42323a8a4f9286ff0b4acced1',
        '4e3e0acc1a99a107cecd750ca4c55e991e2958c93c41164612765a5f78cbf1a9'),
}
POLICY_INPUTS = {'assurance/policy.toml', 'assurance/zeroization-matrix.toml',
                 'assurance/constant-time-matrix.toml', 'rust-toolchain.toml'}


def prove(root, base, changed):
    """Return source-eligible families; never command coverage or run permission.

Only callers that already validated an ancestor receipt use this proof. All
changed paths are recomputed, and the ordinary semantic scope checks classify
everything except these three exact reviewed Miri-only files. No family with
changed Rust tests/implementations is exempted. Unknown deltas fail closed.
"""
    try:
        if (set(changed) != set(plans.changed_paths(root, base))
                or not set(changed).intersection(REVISIONS)
                or set(changed).intersection(POLICY_INPUTS)):
            return set()
        compiler = plans.inputs.document((root / 'rust-toolchain.toml').read_bytes())['toolchain']['channel']
        if plans.environment_issues(dict(os.environ), compiler):
            return set()
        for path, expected in REVISIONS.items():
            before, after = plans.inputs.snapshot(root, base, path)
            if before is None or after is None:
                return set()
            actual = tuple(hashlib.sha256(raw).hexdigest() for raw in (before, after))
            if actual != expected:
                return set()
        downstream = miri_dependencies.graph(*plans.inputs.snapshot(root, base, 'Cargo.lock'))
        full, affected = plans.scope.select_repository(
            base, root, verified_base=True, downstream=downstream, include_miri_tasks=False)
        return set() if full else set(plans.scope.GROUPS) - set(affected)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return set()
