"""Reuse pre-HMAC execution paths only after exact feature-inactive proof.

Callers authenticate original artifacts and validate their result populations
first. This module cannot approve an artifact, a new capture or a new HMAC path.
"""
import tomllib

import native_review_io as io
import native_review_scope as scope
import native_hmac_profile as profile


def fixture_pin(root, capture, head, name, after):
    for family, quote in (('tuplehash', '"'), ('parallelhash', "'")):
        if name != f'scripts/{family}/{family}_reviewed_hashes.py':
            continue
        fixture = f'assurance/{family}-public-api/Cargo.toml'
        old, new = (io.raw_blob(root, revision, fixture) for revision in (capture, head))
        if old == new:
            return after
        old_version, new_version = (
            tomllib.loads(io.raw_blob(root, revision, 'crates/brynja/Cargo.toml').decode())
            ['package']['version'] for revision in (capture, head))
        for raw, version in ((old, old_version), (new, new_version)):
            io.require(tomllib.loads(raw.decode())['dependencies']['brynja']['version'] == '=' + version,
                       'HMAC projection fixture/facade version mismatch')
        old_token = f'version = "={old_version}"'.encode()
        new_token = f'version = "={new_version}"'.encode()
        io.require(old_version != new_version and old.count(old_token) == 1 and
                   old.replace(old_token, new_token, 1) == new,
                   'HMAC projection cannot exempt fixture code/features')
        new_pin = f'{quote}{fixture}{quote}: {quote}{io.sha(new)}{quote}'.encode()
        old_pin = f'{quote}{fixture}{quote}: {quote}{io.sha(old)}{quote}'.encode()
        io.require(after.count(new_pin) == 1, 'HMAC projection fixture pin missing/ambiguous')
        return after.replace(new_pin, old_pin, 1)
    return after


def validate_inputs(root, capture, head, current, captured, digest, validation_changes, family):
    io.require(family in profile.FIXTURES, 'HMAC projection is not qualification for this family')
    io.require(set(captured) <= set(current) and
               set(current) - set(captured) <= profile.ADDED and
               not (set(captured) & profile.ADDED), 'unexpected inactive HMAC input population')
    io.require(profile.PREFIX + 'Cargo.toml' in captured,
               'inactive HMAC projection requires captured hosted manifest')
    io.git(root, 'merge-base', '--is-ancestor', capture, head)
    for name, expected in captured.items():
        io.require(digest(name, io.historical(root, capture, name)) == expected,
                   'original native source binding changed: ' + name)
    for name, expected in current.items():
        io.require(digest(name, io.historical(root, head, name)) == expected,
                   'current native source binding changed: ' + name)
    # Even owner approval of a validation helper does not permit a change to
    # these independently reviewed capture commands/feature selectors.
    profile.command_profile(root, capture, head, family)
    io.require(set(validation_changes) <= set(captured), 'approved validation input absent')
    for name, pair in validation_changes.items():
        before = io.raw_blob(root, capture, name)
        after = fixture_pin(root, capture, head, name, io.raw_blob(root, head, name))
        io.require(io.sha(before) == pair['before'] and io.sha(after) == pair['after'],
                   'reviewed validation bytes changed: ' + name)
    # Include orphan source, build scripts, feature configuration and fixture
    # additions; collector source lists alone are not a complete scope boundary.
    closure = set(current) | set(captured)
    old = {n: v for n, v in io.tree(root, capture).items() if scope.selected(n, closure)}
    new = {n: v for n, v in io.tree(root, head).items() if scope.selected(n, closure)}
    io.require(set(old) <= set(new) and set(new) - set(old) <= profile.ADDED,
               'unexpected family addition/removal outside inactive HMAC modules')
    io.require(all(value.startswith(('100644 blob ', '100755 blob ')) for value in new.values()),
               'nonregular inactive HMAC input')
    for name in closure:
        if name.startswith('crates/') and name.endswith('/Cargo.toml'):
            for revision, inventory in ((capture, old), (head, new)):
                manifest = tomllib.loads(io.raw_blob(root, revision, name).decode())
                io.require(manifest['package'].get('build', False) is False and
                           name.removesuffix('Cargo.toml') + 'build.rs' not in inventory,
                           'custom build script requires exact native metadata')
    for name in old:
        if old[name] == new[name]:
            continue
        before, after = (io.raw_blob(root, revision, name) for revision in (capture, head))
        if name in validation_changes or profile.source_only(name, before, after):
            continue
        if name == profile.PREFIX + 'Cargo.toml' and profile.hosted_manifest(before, after):
            continue
        if name == 'Cargo.toml' and profile.workspace(before, after):
            continue
        if name == 'Cargo.lock' and profile.lock(root, capture, head):
            continue
        if fixture_pin(root, capture, head, name, after) == before:
            continue
        io.require(False, 'active native input changed outside inactive HMAC projection: ' + name)
