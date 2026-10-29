"""Bound a family's original inputs without coupling it to unrelated crates."""
import tomllib

import native_review_io as io
import native_tooling_review as tooling
import native_dependency_scope as dependencies


def selected(name, closure):
    # Keep additions/deletions, build scripts and orphan sources inside every
    # participating crate/fixture visible, not just currently enumerated files.
    roots = {'/'.join(path.split('/')[:2]) + '/' for path in closure
             if path.startswith(('crates/', 'assurance/')) and len(path.split('/')) > 2}
    return (name in closure or name in {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
                                       'rust-toolchain'} or name.startswith('.cargo/') or
            io.protected(name) and any(name.startswith(prefix) for prefix in roots))


def lock(root, revision):
    value = tomllib.loads(io.historical(root, revision, 'Cargo.lock').decode())
    # The top-level facade's version is not an implementation input to a leaf
    # capture. No dependency, checksum, source, feature or other package changes
    # are discarded. Require the facade manifest to corroborate the version.
    rows = value.get('package', [])
    facade = [row for row in rows if row.get('name') == 'brynja']
    if facade:
        io.require(len(facade) == 1, 'ambiguous facade lock identity')
        manifest = tomllib.loads(io.historical(root, revision, 'crates/brynja/Cargo.toml').decode())
        io.require(facade[0]['version'] == manifest['package']['version'], 'facade lock version drift')
        facade[0]['version'] = '<facade-version>'
    return value


def unchanged(root, before, after, closure, reviewed_validation=frozenset(), dependency_profile=None):
    previous = {n: v for n, v in io.tree(root, before).items() if selected(n, closure)}
    current = {n: v for n, v in io.tree(root, after).items() if selected(n, closure)}
    io.require(set(previous) == set(current), 'family implementation/build input addition/removal')
    for name, identity in previous.items():
        io.require(current[name].startswith(('100644 blob ', '100755 blob ')),
                   'nonregular family input: ' + name)
        if identity == current[name]:
            continue
        # The caller checked both raw digests against either the externally
        # pinned validation review or the exact source-bound test decomposition.
        # External artifact approval and population/type checks still apply.
        if name in reviewed_validation:
            continue
        io.require((name == 'Cargo.lock' and lock(root, before) == lock(root, after)) or
                   (name in {'Cargo.toml', 'Cargo.lock'} and
                    dependencies.equivalent(root, before, after, closure, dependency_profile)) or
                   (dependencies.manifest_equivalent(root, before, after, name, dependency_profile) and
                    dependencies.equivalent(root, before, after, closure, dependency_profile)) or
                   tooling.equivalent(root, before, after, name),
                   'family implementation/build input changed: ' + name)
