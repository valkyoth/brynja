"""Reuse original accepted results only for unchanged captured inputs.

This proves source/build equivalence, not a fresh execution, new compiler or
platform claim. Historical result validators still validate every original lane.
"""
import native_dependency_scope as dependencies
import native_review_io as io
import native_review_scope as scope


def validate_inputs(root, capture, head, current, captured, digest, validation_changes=None,
                    dependency_profile=None):
    io.require(set(current) == set(captured), 'native input population changed')
    changes = validation_changes or {}
    io.require(set(changes) <= set(captured), 'reviewed validation input absent from capture')
    for name, row in changes.items():
        io.committed(root, name, head)
        io.require(io.sha(io.raw_blob(root, capture, name)) == row['before'] and
                   io.sha(io.raw_blob(root, head, name)) == row['after'],
                   'reviewed validation bytes changed: ' + name)
    io.git(root, 'merge-base', '--is-ancestor', capture, head)
    metadata = {'Cargo.toml', 'Cargo.lock'}
    changed_metadata = False
    for name, expected in captured.items():
        io.require(digest(name, io.historical(root, capture, name)) == expected,
                   'original native source binding changed: ' + name)
        if current[name] != expected:
            if name in changes:
                continue
            io.require(name in metadata, 'native implementation/fixture/tool changed: ' + name)
            changed_metadata = True
    if changed_metadata:
        io.require(dependencies.equivalent(root, capture, head, current, dependency_profile),
                   'native dependency/build inputs changed')
    # Include newly added/deleted source, build scripts and configuration, even
    # where an older collector enumerated only src/**/*.rs.
    scope.unchanged(root, capture, head, current, reviewed_validation=set(changes),
                    dependency_profile=dependency_profile)


def validate_family(adapter, head):
    from native_evidence_approval import validate
    review = validate(adapter.name, adapter.root, head)
    capture = review['capture_commit']
    captured, count = adapter.records(review, head)
    current = adapter.sources()
    profile = None
    if adapter.name in ('md5-execution', 'md5-hardened'):
        from native_md5_dependency_profile import PROFILE
        profile = PROFILE
    validate_inputs(adapter.root, capture, head, current, captured, adapter.digest,
                    review['validation_changes'], profile)
    io.clean(adapter.root)
    io.require(io.git(adapter.root, 'rev-parse', 'HEAD').decode().strip() == head and
               adapter.sources() == current, 'checkout changed during native reuse')
    print(f'{adapter.name} native evidence: REUSED; {count} accepted records at {capture}; '
          f'implementation/build inputs unchanged; {len(review["validation_changes"])} '
          'exact validation-only changes approved. Original compiler and platform '
          'claims only; not a fresh capture, independent review or certification.')
