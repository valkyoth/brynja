"""Exact strict-facade feature closure; no relaxation of ordinary facade isolation."""
import copy

DIRECT = {
    'brynja-crypto-cpu-std': ['strict-sha2', 'strict-sha3', 'strict-kmac', 'strict-tuplehash', 'strict-batch'],
    'brynja-hash-parallel-std': ['strict-execution'],
}
FEATURES = {'default': [], 'acceleration': [
    'brynja-crypto-cpu-std/strict-sha2-acceleration',
    'brynja-crypto-cpu-std/strict-sha3-acceleration',
    'brynja-crypto-cpu-std/strict-kmac-acceleration',
    'brynja-crypto-cpu-std/strict-tuplehash-acceleration',
    'brynja-hash-parallel-std/strict-acceleration',
]}
# Cargo resolves every workspace root together, including the mandatory strict
# facade, even for --no-default-features. These are fixed reviewed additions,
# never copied from the metadata being validated.
UNIFIED = {
    'brynja-crypto-cpu': ['keccak-hardened-batch', 'sha256-hardened-batch', 'sha512-hardened-batch'],
    'brynja-crypto-cpu-std': ['keccak-hardened-batch', 'protected-memory', 'sha256-hardened-batch',
        'sha512-hardened-batch', 'strict-batch', 'strict-kmac', 'strict-sha2', 'strict-sha3', 'strict-tuplehash'],
    'brynja-hash-parallel-std': ['strict-execution'],
    'brynja-hash-sha2': ['general-sha512-t', 'hardened-batch-execution', 'hardened-batch512-execution'],
    'brynja-hash-sha3': ['cpu', 'hardened-batch-execution'],
}
EDGES = {
    'brynja-crypto-cpu-std': ['brynja-core', 'brynja-hash-sha3', 'brynja-mac-kmac', 'brynja-hash-tuple'],
    'brynja-hash-parallel-std': ['brynja-crypto-cpu-std'],
    'brynja-hash-sha3': ['brynja-crypto-cpu'],
}


def regressions(all_features, dependency, package, require_rejection):
    for owner in ('brynja-crypto-cpu-std', 'brynja-hash-parallel-std'):
        for field, value, message in (
            ('features', [], 'directly enables features'),
            ('uses_default_features', True, 'default-feature policy drifted'),
            ('optional', True, 'optionality drifted'),
        ):
            changed = copy.deepcopy(all_features)
            dependency(changed, 'brynja-strict', owner)[field] = value
            require_rejection(changed, 'all-features', message,
                              'weakened mandatory strict facade dependency')
    for key, value in (('default', ['acceleration']), ('acceleration', [])):
        changed = copy.deepcopy(all_features)
        package(changed, 'brynja-strict')['features'][key] = value
        require_rejection(changed, 'all-features', 'feature policy differs',
                          'strict facade acceleration drift')
    changed = copy.deepcopy(all_features)
    package(changed, 'brynja-strict')['homepage'] = 'https://github.com/valkyoth/brynja'
    require_rejection(changed, 'all-features', 'unexpected homepage metadata',
                      'redundant facade homepage')
    print('Strict facade rejects nine dependency, feature and metadata regressions')
