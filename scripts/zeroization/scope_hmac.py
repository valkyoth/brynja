"""Narrow HMAC integration deltas; never exempt a shared facade or CPU crate."""
import copy
import tomllib

LEAF = 'brynja-mac-hmac'
CONSUMERS = frozenset({'brynja-crypto', 'brynja-crypto-cpu-std'})
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
    'crates/brynja-crypto-cpu-std/src/execution/mod.rs': (
        (b'//! Explicit hosted selection for ordinary raw kernels, not complete hashes.\n',
         b'//! Explicit hosted selection for raw kernels and opt-in hardened HMAC.\n'),
        (b'', b'#[cfg(feature = "hmac-execution")]\nmod hmac;\n'),
        (b'', b'#[cfg(feature = "hmac-execution")]\npub use hmac::HmacError;\n')),
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
}
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
    replacements = {**SOURCES, **PACKAGING, **COMPOSITION}.get(path)
    if replacements is None or before is None or after is None:
        return False
    values = []
    for raw in (before, after):
        for old, new in replacements:
            if raw.count(new) > 1:
                return False
            if old and raw.count(old) + raw.count(new) != 1:
                return False
            raw = raw.replace(new, old)
        values.append(raw)
    return values[0] == values[1]


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
