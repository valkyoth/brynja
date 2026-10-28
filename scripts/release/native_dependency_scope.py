"""Project workspace metadata onto the dependencies of an existing capture.

No Cargo execution, new receipts, or version-specific exemptions. Optional/dev
edges are conservative unless an exact reviewed command profile proves inactivity.
Ambiguous graphs require review.
"""
import copy
import tomllib

import native_review_io as io
import native_md5_dependency_profile as md5
import native_sha1_dependency_profile as sha1
import native_publication_metadata as publication


def graph(raw):
    data = tomllib.loads(raw.decode())
    io.require(set(data) == {'version', 'package'} and data['version'] == 4,
               'unknown dependency lock schema')
    rows = {}
    for row in data['package']:
        name = row['name']
        io.require(isinstance(name, str) and name not in rows,
                   'ambiguous dependency identity')
        edges = row.get('dependencies', [])
        io.require(isinstance(edges, list) and all(isinstance(edge, str) and
                   len(edge.split()) == 1 for edge in edges) and
                   len(edges) == len(set(edges)), 'ambiguous dependency edge')
        rows[name] = row
    io.require(all(edge in rows for row in rows.values()
                   for edge in row.get('dependencies', [])), 'unresolved dependency edge')
    return rows


def reachable(rows, roots):
    io.require(bool(roots), 'missing capture package roots')
    found, pending = set(), list(roots)
    while pending:
        name = pending.pop()
        if name in found:
            continue
        io.require(name in rows, 'capture dependency missing: ' + name)
        found.add(name)
        pending.extend(rows[name].get('dependencies', []))
    return found


def inherited_dependencies(value):
    """Include target, build and dev tables; aliases use their workspace key."""
    found = set()
    if isinstance(value, dict):
        for name, child in value.items():
            if name in {'dependencies', 'build-dependencies', 'dev-dependencies'}:
                io.require(isinstance(child, dict), 'invalid dependency table')
                found.update(key for key, spec in child.items()
                             if isinstance(spec, dict) and spec.get('workspace') is True)
            else:
                found.update(inherited_dependencies(child))
    return found


def manifest_equivalent(root, before, after, name, profile=None):
    if publication.equivalent(root, before, after, name, profile):
        return True
    module = {sha1.PROFILE: sha1, md5.PROFILE: md5}.get(profile)
    if module is None or name != module.MANIFEST:
        return False
    return (module.manifest_bytes(root, before, publication.raw(root, before, name, profile)) ==
            module.manifest_bytes(root, after, publication.raw(root, after, name, profile)))


def projection(root, revision, closure, profile=None):
    names = io.names(root, revision)
    roots = {'/'.join(name.split('/')[:2]) for name in closure
             if name.startswith('crates/') and len(name.split('/')) > 2}
    io.require(bool(roots), 'capture contains no implementation roots')
    manifests = {}
    for name in sorted(names):
        if name.startswith('crates/') and name.count('/') == 2 and name.endswith('/Cargo.toml'):
            raw = publication.raw(root, revision, name, profile)
            if profile == sha1.PROFILE and name == sha1.MANIFEST:
                raw = sha1.manifest_bytes(root, revision, raw)
            elif profile == md5.PROFILE and name == md5.MANIFEST:
                raw = md5.manifest_bytes(root, revision, raw)
            manifest = tomllib.loads(raw.decode())
            package = manifest['package']['name']
            io.require(package not in manifests, 'duplicate local package identity')
            manifests[package] = (name, manifest)
    package_roots = {package for package, (name, _) in manifests.items()
                     if name.removesuffix('/Cargo.toml') in roots}
    io.require(len(package_roots) == len(roots), 'missing capture package manifest')
    rows = graph(publication.raw(root, revision, 'Cargo.lock', profile))
    traversal = rows
    if profile is not None:
        profiles = {md5.PROFILE: md5, sha1.PROFILE: sha1}
        io.require(profile in profiles, 'unknown native dependency command profile')
        traversal = profiles[profile].reachability_rows(root, revision, closure, rows)
    selected = reachable(traversal, package_roots)
    inherited, local = set(), {}
    for package in selected:
        row = rows[package]
        if 'source' in row:
            continue
        io.require(package in manifests, 'unmapped local dependency: ' + package)
        name, manifest = manifests[package]
        io.require(name.removesuffix('/Cargo.toml') in roots,
                   'local dependency absent from capture closure: ' + package)
        # A custom build script may inspect arbitrary workspace metadata. Do
        # not infer Cargo-only semantics for such a package from its lock graph.
        io.require(manifest['package'].get('build', False) is False and
                   name.removesuffix('Cargo.toml') + 'build.rs' not in names,
                   'custom build script requires exact native metadata')
        version = manifest['package']['version']
        if version == {'workspace': True}:
            workspace = tomllib.loads(io.historical(root, revision, 'Cargo.toml').decode())
            version = workspace['workspace']['package']['version']
        io.require(version == row['version'], 'local manifest/lock identity differs')
        local[name] = manifest
        inherited.update(inherited_dependencies(manifest))
    # Fixtures can inherit workspace dependencies too. Their own manifests and
    # locks are still compared byte-for-byte by the native source validator.
    for name in closure:
        if name.startswith('assurance/') and name.endswith('/Cargo.toml'):
            inherited.update(inherited_dependencies(
                tomllib.loads(io.historical(root, revision, name).decode())))
    workspace = copy.deepcopy(tomllib.loads(publication.raw(root, revision, 'Cargo.toml', profile).decode()))
    dependencies = workspace.get('workspace', {}).get('dependencies', {})
    io.require(inherited <= dependencies.keys(), 'unresolved inherited dependency')
    if 'dependencies' in workspace.get('workspace', {}):
        workspace['workspace']['dependencies'] = {key: dependencies[key] for key in sorted(inherited)}
    # Resolver, members, patches, profiles, inherited package values and lints
    # remain exact. This does not assume workspace feature unification is inert.
    return {'workspace': workspace, 'lock': {key: rows[key] for key in sorted(selected)},
            'manifests': local}


def equivalent(root, before, after, closure, profile=None):
    try:
        return projection(root, before, closure, profile) == projection(root, after, closure, profile)
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('malformed native dependency metadata') from error
