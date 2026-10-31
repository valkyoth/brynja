"""Narrow HMAC integration deltas; never exempt a shared facade or CPU crate."""
import copy
import hashlib
import tomllib

LEAF = 'brynja-mac-hmac'
CONSUMERS = frozenset({'brynja-crypto', 'brynja-crypto-cpu-std'})
HOSTED_EXPORT_PATH = 'crates/brynja-crypto-cpu-std/src/execution/mod.rs'
HOSTED_EXPORTS = (
    b'#[cfg(feature = "hmac-execution")]\npub use hmac::HmacError;\n',
    b'#[cfg(feature = "hmac-execution")]\npub use hmac::{HmacError, HmacSelection, PortableHmac};\n',
)
FEATURES = {
    'brynja': {
        'hmac-hardened-execution': ['brynja-crypto/hmac-hardened-execution'],
        'hmac-runtime-execution': ['brynja-crypto/hmac-runtime-execution'],
    },
    'brynja-crypto': {
        'hmac-hardened-execution': ['cpu', LEAF + '/hardened-execution'],
        'hmac-runtime-execution': ['cpu', LEAF + '/runtime-execution'],
    },
    'brynja-crypto-cpu-std': {
        'hmac-execution': ['runtime-execution', 'dep:' + LEAF, LEAF + '/runtime-execution'],
        'strict-hmac': ['protected-memory', 'dep:' + LEAF],
        'strict-hmac-acceleration': ['strict-hmac', LEAF + '/hardened-execution'],
        'macos-resident-hmac': ['macos-resident', 'dep:' + LEAF],
        'macos-resident-hmac-acceleration': ['macos-resident-hmac', LEAF + '/hardened-execution'],
    },
}
SOURCES = {
    'crates/brynja-strict/src/lib.rs': (
        (b'', b'pub mod hmac;\n\n'),
        (b'', b'\n#[cfg(test)]\nmod hmac_tests;\n')),
    'crates/brynja-crypto/src/lib.rs': ((b'',
        b'/// Modern sealed HMAC construction; development implementation, qualification pending.\n'
        b'/// Portable by default; neither this namespace nor its execution opt-ins promise\n'
        b'/// protected host memory. No legacy HMAC, arbitrary digest plug-ins or key export.\n'
        b'pub mod hmac;\n'),),
    'crates/brynja-crypto-cpu-std/src/lib.rs': (
        (b'', b'#[cfg(feature = "strict-hmac")]\npub mod strict_hmac;\n'),),
    HOSTED_EXPORT_PATH: (
        (b'//! Explicit hosted selection for ordinary raw kernels, not complete hashes.\n',
         b'//! Explicit hosted selection for raw kernels and opt-in hardened HMAC.\n'),
        (b'', b'#[cfg(feature = "hmac-execution")]\nmod hmac;\n'),
        (b'', HOSTED_EXPORTS[1])),
    'crates/brynja-crypto-cpu-std/src/macos_resident/mod.rs': (
        (b'', b'#[cfg(feature = "macos-resident-hmac")]\npub mod hmac;\n'),
        (b'    any(feature = "macos-resident-kmac", feature = "macos-resident-tuplehash")\n',
         b'    any(\n        feature = "macos-resident-kmac",\n'
         b'        feature = "macos-resident-tuplehash",\n'
         b'        feature = "macos-resident-hmac"\n    )\n')),
}
PACKAGING = {
    # Adding the new dependency archive changes resolution, not any of the
    # historical worker tests. Every other byte remains part of shared scope.
    'scripts/cryptography/check-strict-profile-package.py': (
        (b"        'brynja-strict')\n",
         b"        'brynja-mac-hmac', 'brynja-strict')\n"),),
    'scripts/cryptography/check-macos-legacy-resident-package.py': (
        (b'', b"            'brynja-mac-hmac',\n"),),
    **dict.fromkeys(('scripts/md5/check-md5-package.py',
                     'scripts/sha1/check-sha1-package.py'), (
        (b"'brynja-mac-kmac', 'brynja-hash-tuple')})",
         b"'brynja-mac-kmac', 'brynja-hash-tuple', 'brynja-mac-hmac')})"),)),
    'scripts/sha2/check-sha2-execution.py': (
        (b"'brynja-hash-tuple', 'brynja-crypto-cpu-std')",
         b"'brynja-hash-tuple', 'brynja-mac-hmac', 'brynja-crypto-cpu-std')"),),
    'scripts/sha3/check-sha3-execution.py': (
        (b"packages = tuple(dict.fromkeys((*PACKAGES, 'brynja-mac-kmac', 'brynja-hash-tuple')))",
         b"packages = tuple(dict.fromkeys((*PACKAGES, 'brynja-mac-kmac', 'brynja-hash-tuple',\n"
         b"                                   'brynja-mac-hmac')))"),),
    'scripts/sha2/sha256_policy.py': (
        (b'', b'        "brynja-mac-hmac",\n'),),
}
# Existing prefixes remain byte-identical; only these reviewed gated test
# suffixes belong to HMAC. Editing any older worker test selects its consumers.
TEST_SUFFIXES = {
    'crates/brynja-crypto-cpu-std/src/protected_memory/platform/thread/tests.rs':
        'd19d2744657bd2b8d8a05b175304db2cc741d43fa85dcbf88b9170f72248da42',
    'crates/brynja-crypto-cpu-std/src/macos_resident/resource/darwin/tests.rs':
        '875ce1f721f6ecad339188a3b95e6e4c199d7eaadaca4a518cdeb8d5a46937d8',
}
HOSTED_SOURCES = {'src/execution/hmac.rs': 'opt-in-hardened-hmac-adapter'}
for directory, prefix, scalar, policy, tests in (
    ('strict_hmac', 'protected', 'scalar-', 'policy-and-bounds', 'model-and-fault-tests'),
    ('macos_resident/hmac', 'macos-resident', '', 'api-types', 'admission-tests'),
):
    HOSTED_SOURCES.update({f'src/{directory}/{name}': f'{prefix}-{status}' for name, status in {
        'mod.rs': scalar + 'hmac-session-development', 'types.rs': 'hmac-' + policy,
        'worker.rs': 'hmac-worker' + ('-and-verification' if directory == 'strict_hmac' else ''),
        'tests.rs': 'hmac-' + tests,
        'tests/native.rs': 'hmac-native-tests',
        'compiled.rs': ('compiled-hmac' if directory == 'strict_hmac' else 'hmac-compiled') + '-session-development',
        'compiled/worker.rs': ('compiled-hmac' if directory == 'strict_hmac' else 'hmac-compiled') + '-worker',
        'compiled/tests.rs': ('compiled-hmac' if directory == 'strict_hmac' else 'hmac-compiled') + '-admission-tests',
        'compiled/tests/native.rs': ('compiled-hmac' if directory == 'strict_hmac' else 'hmac-compiled') + '-native-tests',
    }.items()})
# Whole-file reviewed HMAC-only tooling additions. These are scope identities,
# not authorizations or successful execution receipts. Changed command drivers
# still run, and current CPU/SHA-2 policy checks remain mandatory.
TOOL_PAIRS = {
    'scripts/cpu/check-hosted-execution.py': (
        '05c40d7c72890f5e9904470c3233cca7e46aa0b1ed309819b2028d399e0d15e9',
        '462e9e8dda87ebc404f046a601ac1245081e4769388314a24c8ce17f1c297f1d'),
    'scripts/cpu/cpu_boundary_backends.py': (
        'd5d214aaf9da4130a8e0f0278861c8eb57a5b3f5253a2a3a527265735f8b9105',
        '9e5afb5958db04d837d9f952c068c861016d3d4c7913e54b89636f9e38aea2bf'),
    'scripts/sha2/test-sha256.py': (
        'f74fa4de3a5c70cc4b32e925bf6bb053f6b63f52e754eb59ba2e67cadc39dd9e',
        '4802718f2754dc3c8faafa866c058e7960a55398f41dc179bc14b99fcc7f5c75'),
}
# Exact reviewed test-only addition: optional archive closure/graph regressions.
# Its command stays mandatory; any later edit retains broad shared scope.
PACKAGING_TEST = 'scripts/cryptography/test-macos-legacy-resident-package.py'
PACKAGING_TEST_HASHES = frozenset({
    'f71826a32760bd920caa55714205ced223c7c911328f93beb8e871e035a3a18c',
    '5dd8870dd0f0ed3b8d4d5611397aa70e171e826b4cdd9f9bb53362c0530c22ad',
})
COMPOSITION = {
    # Add only the HMAC composition registration and metadata renderer pin.
    # Every existing direct owner, MIR identity and compiler test is unchanged.
    'scripts/cryptography/api_profile_contracts.py': (
        (b'', b'import hmac_owner_contract\n'),
        (b'', b'# The direct-destructor MIR checker intentionally handles only the original\n'
         b'# map. Composed owners bind their distinct emitted-code pipeline explicitly.\n'
         b'COMPOSED_OWNER_CONTRACTS = {hmac_owner_contract.ID: {"record": hmac_owner_contract.RECORD}}\n\n'),
        (b'', b'    "scripts/cryptography/api_profile_render.py",\n'),
        (b'', b'\nREVIEWED_SOURCE_PATHS.update(hmac_owner_contract.reviewed_paths())\n')),
}


def strict_manifest(before, after):
    """Only two HMAC forwarding additions; every other strict option is retained."""
    values = []
    for raw in (before, after):
        if raw is None:
            return False
        value = tomllib.loads(raw.decode())
        if value.get('package', {}).get('name') != 'brynja-strict':
            return False
        value['package'].pop('version', None)
        try:
            direct = value['dependencies']['brynja-crypto-cpu-std']['features']
            accelerated = value['features']['acceleration']
            for features, entry in ((direct, 'strict-hmac'),
                                   (accelerated, 'brynja-crypto-cpu-std/strict-hmac-acceleration')):
                if not isinstance(features, list) or len(features) != len(set(features)):
                    return False
                if entry in features:
                    features.remove(entry)
        except (KeyError, TypeError):
            return False
        values.append(value)
    return values[0] == values[1]


def manifest_only(path, before, after):
    if path == 'crates/brynja-strict/Cargo.toml':
        return strict_manifest(before, after)
    names = {f'crates/{name}/Cargo.toml': name for name in FEATURES}
    if path not in names or before is None or after is None:
        return False
    name = names[path]
    values = []
    for raw in (before, after):
        value = tomllib.loads(raw.decode())
        if value.get('package', {}).get('name') != name:
            return False
        value['package'].pop('version', None)  # Local version is not code identity.
        for key, expected in FEATURES[name].items():
            actual = value.get('features', {}).pop(key, None)
            if actual is not None and actual != expected:
                return False
        if name in CONSUMERS:
            actual = value.get('dependencies', {}).pop(LEAF, None)
            expected = {'workspace': True}
            if name == 'brynja-crypto-cpu-std':
                expected['optional'] = True
            if actual is not None and actual != expected:
                return False
        values.append(value)
    return values[0] == values[1]


def source_only(path, before, after):
    if path in TEST_SUFFIXES and before is not None and after is not None:
        return any(b.startswith(a) and hashlib.sha256(b[len(a):]).hexdigest() == TEST_SUFFIXES[path]
                   for a, b in ((before, after), (after, before)))
    if path in TOOL_PAIRS:
        return all(raw is not None and hashlib.sha256(raw).hexdigest() in TOOL_PAIRS[path]
                   for raw in (before, after))
    if public_archive_only(path, before, after):
        return True
    if path == PACKAGING_TEST:
        return all(raw is not None and hashlib.sha256(raw).hexdigest() in
                   PACKAGING_TEST_HASHES for raw in (before, after))
    replacements = {**SOURCES, **PACKAGING, **COMPOSITION}.get(path)
    if replacements is None or before is None or after is None:
        return False
    values = []
    for raw in (before, after):
        if path == HOSTED_EXPORT_PATH:
            # Only the two reviewed HMAC export shapes are equivalent for
            # family selection; duplicates and every unrelated byte still fail.
            if sum(raw.count(export) for export in HOSTED_EXPORTS) > 1:
                return False
            raw = raw.replace(HOSTED_EXPORTS[0], HOSTED_EXPORTS[1])
        for old, new in replacements:
            if raw.count(new) > 1:
                return False
            if old and raw.count(old) + raw.count(new) != 1:
                return False
            raw = raw.replace(new, old)
        values.append(raw)
    return values[0] == values[1]


def public_archive_only(path, before, after):
    """Only add the HMAC package/patch plus existing version/digest rebinding."""
    if path not in {'scripts/sha2/sha256_public_api.py', 'scripts/sha2/sha2_public_api.py',
                    'scripts/sha3/sha3_public_api.py'} or before is None or after is None:
        return False
    import ast
    import scope_inputs as inputs
    values, versions = [], []
    additions = [b'    ("brynja-mac-hmac", "0.1.0", ("src/lib.rs",)),\n']
    if path.endswith('sha256_public_api.py'):
        additions.append(b'brynja-mac-hmac = { path = "crates/brynja-mac-hmac", version = "=0.1.0" }\n')
    # An already-present HMAC entry is not a new integration. Without an
    # actual entry delta, let the existing version/digest metadata classifier
    # handle the edit; otherwise a README hash refresh reopens all HMAC work.
    if not any(before.count(item) != after.count(item) for item in additions):
        return False
    for raw in (before, after):
        for addition in additions:
            if raw.count(addition) > 1:
                return False
            raw = raw.replace(addition, b'')
        if path.endswith('sha256_public_api.py'):
            values.append(raw)
            continue
        # Extract only the literal facade version from PACKAGES. Its exact
        # replacement is still checked against all other executable bytes/AST.
        tree = ast.parse(raw)
        tables = [n.value for n in tree.body if isinstance(n, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == 'PACKAGES' for t in n.targets)]
        if len(tables) != 1:
            return False
        entries = ast.literal_eval(tables[0])
        if (not isinstance(entries, (tuple, list))
                or any(not isinstance(entry, (tuple, list)) or len(entry) != 3
                       or not isinstance(entry[0], str) or not isinstance(entry[1], str)
                       for entry in entries)):
            return False
        pins = [entry[1] for entry in entries if entry[0] == 'brynja']
        if len(pins) != 1:
            return False
        versions.append(pins[0])
        values.append(raw)
    return (inputs.facade_pin_only(*values, *versions) if versions
            else inputs.python_bindings_only(*values))


def integration_only(path, before, after):
    return manifest_only(path, before, after) or source_only(path, before, after)


def workspace_only(before, after):
    values = []
    for raw in (before, after):
        if raw is None:
            return False
        value = tomllib.loads(raw.decode())
        entry = value.get('workspace', {}).get('dependencies', {}).pop(LEAF, None)
        if entry is not None and entry != {'path': 'crates/' + LEAF, 'version': '=0.1.0'}:
            return False
        values.append(value)
    return values[0] == values[1]


def lock_edge_only(name, old, new):
    """Only addition/removal of the registered leaf edge, not package changes."""
    if name not in CONSUMERS or old is None or new is None:
        return False
    values = []
    for row in (old, new):
        if set(row) != {'name', 'dependencies'} or row['name'] != name:
            return False  # Caller already removed local version fields.
        value = copy.deepcopy(row)
        edges = value['dependencies']
        if not isinstance(edges, list) or len(edges) != len(set(edges)):
            return False
        value['dependencies'] = [edge for edge in edges if edge != LEAF]
        values.append(value)
    return values[0] == values[1]


def consumers(graph, affected):
    # These exact optional/curated HMAC integration edges do not alter other
    # algorithms in the hosted/facade crates. Their manifest and source edits
    # are separately inspected. All other edges retain normal reverse closure.
    return {name for name, row in graph.items()
            if any(dep in affected and not (dep == LEAF and name in CONSUMERS)
                   for dep in row.get('dependencies', []))}
