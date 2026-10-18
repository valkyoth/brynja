"""Reuse original accepted results only for unchanged captured inputs.

This proves source/build equivalence, not a fresh execution, new compiler or
platform claim. Historical result validators still validate every original lane.
"""
import native_dependency_scope as dependencies
import native_review_io as io
import native_review_scope as scope


def validate_inputs(root, capture, head, current, captured, digest):
    io.require(set(current) == set(captured), 'native input population changed')
    io.git(root, 'merge-base', '--is-ancestor', capture, head)
    metadata = {'Cargo.toml', 'Cargo.lock'}
    changed_metadata = False
    for name, expected in captured.items():
        io.require(digest(name, io.historical(root, capture, name)) == expected,
                   'original native source binding changed: ' + name)
        if current[name] != expected:
            io.require(name in metadata, 'native implementation/fixture/tool changed: ' + name)
            changed_metadata = True
    if changed_metadata:
        io.require(dependencies.equivalent(root, capture, head, current),
                   'native dependency/build inputs changed')
    # Include newly added/deleted source, build scripts and configuration, even
    # where an older collector enumerated only src/**/*.rs.
    scope.unchanged(root, capture, head, current)


def validate_family(adapter, head):
    index = io.document(io.committed(adapter.root, adapter.module.INDEX, head))
    sha1 = adapter.name == 'sha1-hardened'
    rows = index['captures' if sha1 else 'lanes']
    commits = set()
    for row in rows.values():
        record = io.document(io.committed(adapter.root, row['path' if sha1 else 'artifact'], head))
        commits.add(io.revision(record['commit']))
    io.require(len(commits) == 1, 'missing/inconsistent original capture commits')
    capture = commits.pop()
    # The existing adapter checks acceptance, hashes, CPU/lane identities and
    # actual result populations. Passing HEAD as the index reference does not
    # change the capture commit or any raw record.
    captured, count = adapter.records({'capture_commit': capture, 'reviewed_commit': head}, head)
    current = adapter.sources()
    validate_inputs(adapter.root, capture, head, current, captured, adapter.digest)
    io.clean(adapter.root)
    io.require(io.git(adapter.root, 'rev-parse', 'HEAD').decode().strip() == head and
               adapter.sources() == current, 'checkout changed during native reuse')
    print(f'{adapter.name} native evidence: REUSED; {count} accepted records at {capture}; '
          'captured implementation/build inputs unchanged. Original compiler and platform '
          'claims only; not a fresh capture, independent review or certification.')
