"""Exact no_std facade forwarding; no host/legacy/conformance feature admission."""
import copy

# Reviewed independently of Cargo metadata: never learn the expected graph
# from the manifest being tested.
LEAVES = {
    'hmac-hardened-execution': ('brynja-mac-hmac', 'hardened-execution'),
    'hmac-runtime-execution': ('brynja-mac-hmac', 'runtime-execution'),
    'general-sha512-t': ('brynja-hash-sha2', 'general-sha512-t'),
    'sha2-static-execution': ('brynja-hash-sha2', 'static-execution'),
    'sha2-runtime-execution': ('brynja-hash-sha2', 'runtime-execution'),
    'sha2-hardened-execution': ('brynja-hash-sha2', 'hardened-execution'),
    'sha256-batch': ('brynja-hash-sha2', 'batch-execution'),
    'sha512-batch': ('brynja-hash-sha2', 'batch512-execution'),
    'sha256-hardened-batch': ('brynja-hash-sha2', 'hardened-batch-execution'),
    'sha512-hardened-batch': ('brynja-hash-sha2', 'hardened-batch512-execution'),
    'sha3-static-execution': ('brynja-hash-sha3', 'static-execution'),
    'sha3-runtime-execution': ('brynja-hash-sha3', 'runtime-execution'),
    'sha3-hardened-execution': ('brynja-hash-sha3', 'hardened-execution'),
    'keccak-batch': ('brynja-hash-sha3', 'batch-execution'),
    'keccak-hardened-batch': ('brynja-hash-sha3', 'hardened-batch-execution'),
    'kmac-hardened-execution': ('brynja-mac-kmac', 'hardened-execution'),
    'kmac-runtime-execution': ('brynja-mac-kmac', 'runtime-execution'),
    'tuplehash-hardened-execution': ('brynja-hash-tuple', 'hardened-execution'),
    'tuplehash-runtime-execution': ('brynja-hash-tuple', 'runtime-execution'),
    'parallelhash-hardened-execution': ('brynja-hash-parallel', 'hardened-execution'),
    'parallelhash-runtime-execution': ('brynja-hash-parallel', 'runtime-execution'),
    'parallelhash-hardened-batch': ('brynja-hash-parallel', 'hardened-batch-execution'),
}
CRYPTO = {'cpu': ['dep:brynja-crypto-cpu']}
CRYPTO.update({feature: ([] if feature == 'general-sha512-t' else ['cpu']) +
              [owner + '/' + leaf] for feature, (owner, leaf) in LEAVES.items()})
FEATURES = {
    'brynja-crypto': CRYPTO,
    'brynja': {feature: ['brynja-crypto/' + feature] for feature in CRYPTO},
}


def validate_isolation(modern, edges, names, packages, reachable):
    if {'brynja-crypto-cpu-std', 'brynja-hash-parallel-std'}.intersection(modern):
        raise ValueError('modern facade must remain independent of host adapter packages')
    # This is a residual workspace-edge check, NOT proof of protocol isolation.
    # check-facade-package.py independently resolves each extracted protocol in
    # a fresh consumer, checks unmodified edges and rejects real feature mutants.
    # Workspace --all-features unifies the explicitly selected crypto opt-in
    # for protocol dependents too. Remove ONLY these reviewed optional edges when
    # checking protocol isolation. Manifest and resolved-edge validation above
    # still rejects direct or unregistered engine/facade CPU dependencies.
    protocol_edges = {identity: set(deps) for identity, deps in edges.items()}
    protocol_edges[names['brynja-crypto']].discard(names['brynja-crypto-cpu'])
    # HMAC owns an additional direct, default-off CPU edge. The independent
    # extracted protocol consumer checks below never remove either edge.
    protocol_edges[names['brynja-mac-hmac']].discard(names['brynja-crypto-cpu'])
    for engine in ('brynja-tls', 'brynja-tls12', 'brynja-tls13',
                   'brynja-tls13-handshake', 'brynja-dtls', 'brynja-quic-tls'):
        reached = reachable(engine, names, packages, protocol_edges)
        if {'brynja-crypto-cpu', 'brynja-crypto-cpu-std'}.intersection(reached):
            raise ValueError(f'protocol engine reaches a CPU adapter: {engine}')


def regressions(baseline, package, reject):
    count = 0
    for name, features in FEATURES.items():
        for feature in features:
            for replacement in ([], ['brynja-mac-kmac/conformance-testing']):
                changed = copy.deepcopy(baseline)
                package(changed, name)['features'][feature] = replacement
                reject(changed, 'all-features', 'feature policy differs',
                       'missing or redirected facade feature forwarding')
                count += 1
            changed = copy.deepcopy(baseline)
            package(changed, name)['features']['default'] = [feature]
            reject(changed, 'all-features', 'feature policy differs',
                   'facade acceleration enabled by default')
            count += 1
    print(f'Facade forwarding rejects {count} opt-in, missing and redirected edges')
