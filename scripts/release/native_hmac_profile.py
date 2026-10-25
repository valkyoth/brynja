"""Exact inactive HMAC integration proof for the pre-HMAC native commands.

This is not a Cargo feature resolver or an exemption for a directory name.
The reviewed commands/fixtures select hosted runtime-execution, never HMAC.
Every existing source byte outside the listed guarded additions stays exact.
New HMAC implementations and their tests receive NO qualification from this.
Evidence authentication and validation-tool approval remain separate checks.
"""
import tomllib

import native_review_io as io
import native_dependency_scope as dependencies

HOST = 'brynja-crypto-cpu-std'
LEAF = 'brynja-mac-hmac'
LEGACY = {'brynja-legacy-hmac', 'brynja-legacy-hmac-std'}
PREFIX = 'crates/' + HOST + '/'
# Immutable command review, not an evidence snapshot or approval substitute.
COMMAND_REVIEW = '1f8f4e1527f9e91b1b1d26b61b8cfc95339ca835'
FIXTURES = {
    'sha2-hardened': 'sha2-hardened-execution',
    'keccak-hardened': 'sha3-execution',
    'kmac-execution': 'kmac-execution',
    'tuplehash-execution': 'tuplehash-execution',
    'parallelhash-execution': 'parallelhash-differential',
}
DRIVERS = {
    'sha2-hardened': ('sha2/capture-sha2-hardened-native.py',),
    'keccak-hardened': ('sha3/capture-keccak-hardened-native.py',
                       'sha3/check-keccak-hardened.py', 'sha3/check-sha3-execution.py'),
    'kmac-execution': ('kmac/capture-kmac-execution-native.py', 'kmac/check-kmac-execution.py'),
    'tuplehash-execution': ('tuplehash/capture-tuplehash-execution-native.py',
                          'tuplehash/check-tuplehash-execution.py'),
    'parallelhash-execution': ('parallelhash/capture-parallelhash-execution-native.py',
                              'parallelhash/check-parallelhash-execution-differential.py',
                              'parallelhash/check-parallelhash-differential.py'),
}
FEATURES = {
    'hmac-execution': ['runtime-execution', 'dep:' + LEAF, LEAF + '/runtime-execution'],
    'strict-hmac': ['protected-memory', 'dep:' + LEAF],
    'strict-hmac-acceleration': ['strict-hmac', LEAF + '/hardened-execution'],
    'macos-resident-hmac': ['macos-resident', 'dep:' + LEAF],
    'macos-resident-hmac-acceleration': ['macos-resident-hmac', LEAF + '/hardened-execution'],
}
MODULES = {
    PREFIX + 'src/lib.rs': ((b'', b'#[cfg(feature = "strict-hmac")]\npub mod strict_hmac;\n'),),
    PREFIX + 'src/execution/mod.rs': (
        (b'//! Explicit hosted selection for ordinary raw kernels, not complete hashes.\n',
         b'//! Explicit hosted selection for raw kernels and opt-in hardened HMAC.\n'),
        (b'', b'#[cfg(feature = "hmac-execution")]\nmod hmac;\n'),
        (b'', b'#[cfg(feature = "hmac-execution")]\npub use hmac::{HmacError, HmacSelection, PortableHmac};\n')),
    PREFIX + 'src/macos_resident/mod.rs': (
        (b'', b'#[cfg(feature = "macos-resident-hmac")]\npub mod hmac;\n'),
        (b'    any(feature = "macos-resident-kmac", feature = "macos-resident-tuplehash")\n',
         b'    any(\n        feature = "macos-resident-kmac",\n'
         b'        feature = "macos-resident-tuplehash",\n'
         b'        feature = "macos-resident-hmac"\n    )\n')),
}
ADDED = {PREFIX + 'src/execution/hmac.rs', PREFIX + 'tests/hmac.rs'} | {
    PREFIX + 'src/' + directory + '/' + name
    for directory in ('strict_hmac', 'macos_resident/hmac')
    for name in ('mod.rs', 'types.rs', 'worker.rs', 'tests.rs', 'tests/native.rs',
                 'compiled.rs', 'compiled/worker.rs', 'compiled/tests.rs', 'compiled/tests/native.rs')}
# The enclosing macos_resident module is disabled in every frozen command
# profile. These new public wrappers receive no qualification from old captures.
RESIDENT_ADDED = {PREFIX + 'src/macos_resident/memory.rs',
                  PREFIX + 'src/macos_resident/memory/tests.rs'}
ADDED |= RESIDENT_ADDED
# Exact appended, feature-gated test items; no Rust parser or substring-based
# "test-only" exemption. Old contents must remain an identical byte prefix.
TEST_SUFFIXES = {
    PREFIX + 'src/protected_memory/platform/thread/tests.rs':
        'd19d2744657bd2b8d8a05b175304db2cc741d43fa85dcbf88b9170f72248da42',
    PREFIX + 'src/macos_resident/resource/darwin/tests.rs':
        '875ce1f721f6ecad339188a3b95e6e4c199d7eaadaca4a518cdeb8d5a46937d8',
}
PACKAGE = 'scripts/sha3/check-sha3-execution.py'
ARCHIVES = (b"packages = tuple(dict.fromkeys((*PACKAGES, 'brynja-mac-kmac', 'brynja-hash-tuple')))" ,
            b"packages = tuple(dict.fromkeys((*PACKAGES, 'brynja-mac-kmac', 'brynja-hash-tuple',\n"
            b"                                   'brynja-mac-hmac')))")


def replacements(before, after, edits):
    for old, new in edits:
        if new in before or after.count(new) != 1:
            return False
        after = after.replace(new, old, 1)
    return before == after


def source_only(name, before, after):
    if name == PREFIX + 'src/macos_resident/mod.rs':
        declaration = b'pub mod memory;\n'
        if declaration in after:
            if declaration in before or after.count(declaration) != 1:
                return False
            after = after.replace(declaration, b'', 1)
    if name in MODULES:
        return replacements(before, after, MODULES[name])
    if name in TEST_SUFFIXES:
        return after.startswith(before) and io.sha(after[len(before):]) == TEST_SUFFIXES[name]
    return False


def hosted_manifest(before, after):
    old, new = (tomllib.loads(raw.decode()) for raw in (before, after))
    if old['package']['name'] != HOST or new['package']['name'] != HOST:
        return False
    if LEAF in old.get('dependencies', {}) or any(key in old['features'] for key in FEATURES):
        return False
    if new['dependencies'].pop(LEAF, None) != {'workspace': True, 'optional': True}:
        return False
    for key, value in FEATURES.items():
        if new['features'].pop(key, None) != value:
            return False
    # Includes package version, default/old features, target/build/dev edges,
    # links/build scripts and every other package option, not just dependencies.
    return old == new


def workspace(before, after):
    old, new = (tomllib.loads(raw.decode()) for raw in (before, after))
    if LEAF in old['workspace']['dependencies']:
        return False
    for name in ('brynja-legacy-sha1', 'brynja-legacy-md5'):
        if name in new['workspace']['dependencies']:
            if name in old['workspace']['dependencies'] or new['workspace']['dependencies'].pop(name) != {
                    'path': 'crates/' + name, 'version': '=0.1.0', 'default-features': False}:
                return False
    return (new['workspace']['dependencies'].pop(LEAF, None) ==
            {'path': 'crates/' + LEAF, 'version': '=0.1.0'} and old == new)


def lock(root, before, after):
    old, new = (dependencies.graph(io.raw_blob(root, revision, 'Cargo.lock'))
                for revision in (before, after))
    if LEGACY & new.keys():
        for name, edges in (
                ('brynja-legacy-hmac', ['brynja-core', 'brynja-legacy-md5', 'brynja-legacy-sha1']),
                ('brynja-legacy-hmac-std', ['brynja-core', HOST, 'brynja-legacy-hmac'])):
            if name in old or new.pop(name, None) != {
                    'name': name, 'version': '0.1.0', 'dependencies': edges}:
                return False
    if LEAF in old or new.pop(LEAF, None) != {
            'name': LEAF, 'version': '0.1.0',
            'dependencies': ['brynja-core', 'brynja-crypto-cpu', 'brynja-hash-sha2', 'brynja-hash-sha3']}:
        return False
    for name in (HOST, 'brynja-crypto'):
        edges = new[name].get('dependencies', [])
        if LEAF in old[name].get('dependencies', []) or edges.count(LEAF) != 1:
            return False
        new[name]['dependencies'].remove(LEAF)
    # Do not erase versions generally. Corroborate only the top-level facade,
    # which is not a dependency of any of the historical native fixtures.
    for rows, revision in ((old, before), (new, after)):
        facade = tomllib.loads(io.raw_blob(root, revision, 'crates/brynja/Cargo.toml').decode())
        if rows['brynja']['version'] != facade['package']['version']:
            return False
        rows['brynja']['version'] = '<facade-version>'
    return old == new


def command_profile(root, before, after, family):
    io.require(family in FIXTURES, 'unknown inactive HMAC command profile')
    paths = ['scripts/' + path for path in DRIVERS[family]]
    paths += ['scripts/sha2/hardened_native_host.py',
              'assurance/' + FIXTURES[family] + '/Cargo.toml',
              'crates/brynja-crypto-cpu/Cargo.toml']
    for name in paths:
        reviewed = io.raw_blob(root, COMMAND_REVIEW, name)
        io.require(io.raw_blob(root, before, name) == reviewed,
                   'historical HMAC-inactive command profile changed: ' + name)
        current = io.raw_blob(root, after, name)
        io.require(current == reviewed or name == PACKAGE and
                   replacements(reviewed, current, (ARCHIVES,)),
                   'HMAC-inactive command/feature selection changed: ' + name)


def feature_graph(root, graph):
    """Independent metadata cross-check; not an execution or native claim."""
    packages = {p['id']: p for p in graph['packages']}
    io.require(len(packages) == len(graph['packages']), 'duplicate feature-graph package')
    nodes = graph['resolve']['nodes']
    io.require(len({n['id'] for n in nodes}) == len(nodes), 'duplicate resolved feature node')
    hosted = []
    for node in nodes:
        package = packages[node['id']]
        io.require(package['name'] not in LEGACY | {LEAF},
                   'HMAC reachable in historical native feature union')
        if package['name'] == HOST:
            hosted.append(node)
            io.require(package['manifest_path'] == str(root / PREFIX / 'Cargo.toml') and
                       set(node['features']) <= {'default', 'runtime-execution', 'sponge-execution'} and
                       'runtime-execution' in node['features'],
                       'hosted HMAC feature/origin changed')
    io.require(len(hosted) == 1, 'missing/ambiguous hosted feature union')
