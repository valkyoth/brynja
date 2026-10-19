"""Exact reviewed MD5 command profile; not a general Cargo feature resolver.

The pinned collectors select execution/hardened-execution on the leaf and
runtime-execution/runtime-hardened-execution on the hosted crate. Packaged
consumers select the same union; their --all-features checks select consumer
features, NOT every feature of the dependency. Cleanup codegen selects the leaf.
None selects the hosted strict-execution edge into brynja-crypto-cpu-std.

Only that optional edge may be omitted from reachability. Original lock rows,
captured source hashes, build inventory and external evidence approval are still
checked by the caller. A command/manifest change requires a new profile review,
not automatic inference from a successful test or a missing capture input.
"""
import copy

import native_review_io as io

PROFILE = 'md5-native-execution'
ROOTS = frozenset('crates/' + name for name in (
    'brynja-core', 'brynja-hash-core', 'brynja-legacy-md5', 'brynja-legacy-md5-std'))
HOST = 'brynja-legacy-md5-std'
INACTIVE = 'brynja-crypto-cpu-std'
# Reviewed raw committed bytes, not regenerated from candidate files.
# No release number or capture commit exemption: both snapshots must match.
REVIEWED = {
    'crates/brynja-core/Cargo.toml': 'e98247de69314a5ce1f6ecde69c081e03237cb663645483e4b9aed3a04929c5d',
    'crates/brynja-hash-core/Cargo.toml': '780e4e4c0d81b8257594601a03d8915fbdc8f4ecfd15824fe5d23ee0c55483cf',
    'crates/brynja-legacy-md5/Cargo.toml': '895e722a3663ef4791d801d8b10324aa9dc9a9da5b5927834a15c978f051e03c',
    'crates/brynja-legacy-md5-std/Cargo.toml': 'dc5de956df5a893f93e84300d9a1bf602e0337bc9e2fea05bc28e7b5bbd6bf1b',
    'scripts/md5/capture-md5-execution-native.py': 'dfeac0185e50c170934e0bf1f73a613c30b9d5c8cbbf505cd241f3d5fad13c7c',
    'scripts/md5/capture-md5-hardened-native.py': '94ecbc410d7b439cc7d0053dbf9263483dc96bcac3d2e43dbd3b17e0fc62b146',
    'scripts/md5/check-md5-package.py': '4517fcf5027fb03b9c6510b141b6ed0b3fe286dca578632d18b0f9f1afedb2ed',
    'scripts/md5/execution_package.py': '2373218e93cb3c07f47cf96b2cc49b15fa0e7aa3bc728db4831750fb5e74cc40',
    'scripts/md5/md5_hardened_package.py': 'd99b2c720113bbb321d3d677c2db4217d2cca80f100597bd14c28eda682214af',
    'scripts/md5/md5_hardened_codegen.py': '552c48427914a9446b98e4704b730b27e7706f9fedf36d20b2fc6341f8089f2b',
    'scripts/md5/check-md5-hardened-codegen.py': '7d7545dd109dd4c3d1a1c07b23fce055c4c115f30357a18ec9481a930ab001a6',
}


def reachability_rows(root, revision, closure, rows):
    roots = {'/'.join(name.split('/')[:2]) for name in closure
             if name.startswith('crates/') and len(name.split('/')) > 2}
    io.require(roots == ROOTS, 'MD5 command profile requires its exact capture roots')
    for name, expected in REVIEWED.items():
        io.require(io.sha(io.raw_blob(root, revision, name)) == expected,
                   'MD5 dependency command/manifest review changed: ' + name)
    # Preserve the original rows for output/projection comparison. Only the
    # traversal copy loses one reviewed inactive optional edge. No dev, build,
    # target, mandatory or unknown edge is implicitly dropped.
    selected = copy.deepcopy(rows)
    edges = selected[HOST].get('dependencies', [])
    io.require(INACTIVE in edges, 'MD5 reviewed optional edge missing')
    selected[HOST]['dependencies'] = [edge for edge in edges if edge != INACTIVE]
    return selected
