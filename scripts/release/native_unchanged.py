"""Reuse original accepted results only for unchanged captured inputs.

This proves source/build equivalence, not a fresh execution, new compiler or
platform claim. Historical result validators still validate every original lane.
"""
import native_dependency_scope as dependencies
import native_review_io as io
import native_review_scope as scope
import native_evidence_approval as approval_module
import native_md5_dependency_profile as md5
import native_sha1_dependency_profile as sha1
import native_hmac_reuse as hmac_reuse
import native_hmac_profile as hmac_profile
import native_test_reuse as test_reuse


def validate_inputs(root, capture, head, current, captured, digest, validation_changes=None,
                    dependency_profile=None, family=None):
    try:
        unchanged_inputs(root, capture, head, current, captured, digest,
                         validation_changes, dependency_profile)
        return 'unchanged'
    except ValueError:
        docs = test_reuse.readme_changes(root, capture, head, current, captured, family)
        tests = test_reuse.changes(root, capture, head, current, captured, family,
                                  include_readmes=bool(docs))
        tests = {**docs, **tests}
        if tests:
            io.require(not (set(tests) & set(validation_changes or {})),
                       'overlapping native test and validation reviews')
            unchanged_inputs(root, capture, head, current, captured, digest,
                             {**(validation_changes or {}), **tests}, dependency_profile)
            return 'reviewed-test-and-readme' if docs else 'reviewed-test-only'
        if (family not in hmac_profile.FIXTURES or
                hmac_profile.PREFIX + 'Cargo.toml' not in captured):
            raise
        hmac_reuse.validate_inputs(root, capture, head, current, captured, digest,
                                  validation_changes or {}, family)
        return 'inactive-hmac'


def unchanged_inputs(root, capture, head, current, captured, digest, validation_changes=None,
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
            io.require(name in metadata or dependencies.manifest_equivalent(
                root, capture, head, name, dependency_profile),
                'native implementation/fixture/tool changed: ' + name)
            changed_metadata = True
    if changed_metadata:
        io.require(dependencies.equivalent(root, capture, head, current, dependency_profile),
                   'native dependency/build inputs changed')
    # Include newly added/deleted source, build scripts and configuration, even
    # where an older collector enumerated only src/**/*.rs.
    scope.unchanged(root, capture, head, current, reviewed_validation=set(changes),
                    dependency_profile=dependency_profile)


def validate_family(adapter, head):
    review = approval_module.validate(adapter.name, adapter.root, head)
    capture = review['capture_commit']
    captured, count = adapter.records(review, head)
    current = adapter.sources()
    profile = None
    if adapter.name in ('md5-execution', 'md5-hardened'):
        profile = md5.PROFILE
    elif adapter.name == 'sha1-hardened':
        profile = sha1.PROFILE
    mode = validate_inputs(adapter.root, capture, head, current, captured, adapter.digest,
                           review['validation_changes'], profile, adapter.name)
    io.clean(adapter.root)
    io.require(io.git(adapter.root, 'rev-parse', 'HEAD').decode().strip() == head and
               adapter.sources() == current, 'checkout changed during native reuse')
    disposition = {
        'unchanged': 'implementation/build inputs unchanged',
        'reviewed-test-only': 'production/build inputs unchanged; exact reviewed test decomposition; '
                              'original native test population only, NOT a run of changed tests',
        'reviewed-test-and-readme': 'production/build inputs unchanged; exact reviewed README prose '
                                    'and test-only changes; original native test population only, '
                                    'NOT a run of changed tests',
        'inactive-hmac': 'original active inputs unchanged; exact inactive HMAC additions excluded; '
                         'NO HMAC qualification',
    }[mode]
    print(f'{adapter.name} native evidence: REUSED; {count} accepted records at {capture}; '
          f'{disposition}; {len(review["validation_changes"])} '
          'exact validation-only changes approved. Original compiler and platform '
          'claims only; not a fresh capture, independent review or certification.')
