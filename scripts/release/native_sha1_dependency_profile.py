"""Exact SHA-1 native selection; strict hosted dependencies are inactive.

Reviewed at the immutable pre-HMAC capture below: the collector enables leaf
hardened-execution and hosted runtime-hardened-execution. Packaged all-features
selects the generated consumer's two features, not all dependency features.
Codegen and scoped mutations select the leaf. Nothing enables strict-execution.
This proves one optional edge inactive; it never approves changed helper bytes.
"""
import copy
import tomllib

import native_review_io as io
import native_md5_dependency_profile as md5
import native_publication_metadata as publication

PROFILE = 'sha1-native-hardened'
REVIEW = '1f8f4e1527f9e91b1b1d26b61b8cfc95339ca835'
HOST = 'brynja-legacy-sha1-std'
INACTIVE = 'brynja-crypto-cpu-std'
ROOTS = frozenset('crates/' + name for name in (
    'brynja-core', 'brynja-hash-core', 'brynja-legacy-sha1', HOST))
PACKAGE = 'scripts/sha1/check-sha1-package.py'
MANIFEST = 'crates/' + HOST + '/Cargo.toml'
LEAF = 'brynja-legacy-sha1'
DIRECT = b'brynja-legacy-sha1 = { path = "../brynja-legacy-sha1", version = "=0.1.0", features = ["cpu"] }'
INHERITED = b'brynja-legacy-sha1 = { workspace = true, default-features = true, features = ["cpu"] }'
REVIEWED = tuple(root + '/Cargo.toml' for root in sorted(ROOTS)) + tuple(
    'scripts/sha1/' + name for name in (
        'capture-sha1-hardened-native.py', 'capture-sha1-cpu-native.py',
        'hardened_native.py', 'check-sha1-package.py', 'hardened_package.py',
        'hardened_codegen.py', 'check-sha1-hardened-codegen.py'))


def manifest_bytes(root, revision, raw):
    """Canonicalize only the reviewed direct-to-workspace dependency spelling.

    The explicit child true preserves the old implicit default features despite
    the new workspace false. Path, version and selected cpu feature stay exact.
    No general manifest normalization and no permission for implementation drift.
    """
    if INHERITED not in raw:
        return raw
    workspace = tomllib.loads(io.raw_blob(root, revision, 'Cargo.toml').decode())
    io.require(raw.count(INHERITED) == 1 and DIRECT not in raw and
               workspace['workspace']['dependencies'].get(LEAF) == {
                   'path': 'crates/' + LEAF, 'version': '=0.1.0', 'default-features': False},
               'SHA-1 inherited dependency identity/features changed')
    return raw.replace(INHERITED, DIRECT, 1)


def reachability_rows(root, revision, closure, rows):
    roots = {'/'.join(name.split('/')[:2]) for name in closure
             if name.startswith('crates/') and len(name.split('/')) > 2}
    io.require(roots == ROOTS, 'SHA-1 command profile requires its exact capture roots')
    for name in REVIEWED:
        raw = publication.raw(root, revision, name, PROFILE)
        if name == MANIFEST:
            raw = manifest_bytes(root, revision, raw)
        if name == PACKAGE:
            # Same exact archive-list edit as MD5; no other byte is normalized.
            raw = md5.reviewed_bytes(md5.PACKAGE, raw)
        io.require(raw == io.raw_blob(root, REVIEW, name),
                   'SHA-1 dependency command/manifest review changed: ' + name)
    selected = copy.deepcopy(rows)
    edges = selected[HOST].get('dependencies', [])
    io.require(INACTIVE in edges, 'SHA-1 reviewed optional edge missing')
    selected[HOST]['dependencies'] = [edge for edge in edges if edge != INACTIVE]
    return selected
