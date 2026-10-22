"""Exact SHA-1 native selection; strict hosted dependencies are inactive.

Reviewed at the immutable pre-HMAC capture below: the collector enables leaf
hardened-execution and hosted runtime-hardened-execution. Packaged all-features
selects the generated consumer's two features, not all dependency features.
Codegen and scoped mutations select the leaf. Nothing enables strict-execution.
This proves one optional edge inactive; it never approves changed helper bytes.
"""
import copy

import native_review_io as io
import native_md5_dependency_profile as md5

PROFILE = 'sha1-native-hardened'
REVIEW = '1f8f4e1527f9e91b1b1d26b61b8cfc95339ca835'
HOST = 'brynja-legacy-sha1-std'
INACTIVE = 'brynja-crypto-cpu-std'
ROOTS = frozenset('crates/' + name for name in (
    'brynja-core', 'brynja-hash-core', 'brynja-legacy-sha1', HOST))
PACKAGE = 'scripts/sha1/check-sha1-package.py'
REVIEWED = tuple(root + '/Cargo.toml' for root in sorted(ROOTS)) + tuple(
    'scripts/sha1/' + name for name in (
        'capture-sha1-hardened-native.py', 'capture-sha1-cpu-native.py',
        'hardened_native.py', 'check-sha1-package.py', 'hardened_package.py',
        'hardened_codegen.py', 'check-sha1-hardened-codegen.py'))


def reachability_rows(root, revision, closure, rows):
    roots = {'/'.join(name.split('/')[:2]) for name in closure
             if name.startswith('crates/') and len(name.split('/')) > 2}
    io.require(roots == ROOTS, 'SHA-1 command profile requires its exact capture roots')
    for name in REVIEWED:
        raw = io.raw_blob(root, revision, name)
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
