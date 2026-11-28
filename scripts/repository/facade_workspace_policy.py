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
CRYPTO = {'cpu': ['dep:brynja-crypto-cpu'], 'aes-gcm': [], 'gmac': [], 'hazmat-aes-block': [], 'hazmat-ghash': [], 'external-key-provider': []}
CRYPTO.update({feature: ([] if feature == 'general-sha512-t' else ['cpu']) +
              [owner + '/' + leaf] for feature, (owner, leaf) in LEAVES.items()})
for feature in ('hazmat-aes-block', 'external-key-provider'):
    CRYPTO[feature] = ['dep:brynja-cipher-aes', 'brynja-cipher-aes/' + feature]
CRYPTO['cpu'].append('brynja-universal-hash-ghash?/cpu')
CRYPTO['hazmat-ghash'] = ['dep:brynja-universal-hash-ghash', 'brynja-universal-hash-ghash/hazmat-ghash']
for feature in ('aes-gcm', 'gmac'):
    CRYPTO[feature] = ['dep:brynja-aead-gcm', 'brynja-aead-gcm/' + feature]
CRYPTO['aes-static-execution'] = ['hazmat-aes-block', 'cpu', 'brynja-cipher-aes/aes-static-execution']
for composition in ('aes-gcm', 'gmac'):
    CRYPTO[composition + '-execution'] = [composition, 'brynja-aead-gcm/' + composition + '-execution']
CRYPTO['aes-runtime-execution'] = ['aes-static-execution', 'brynja-cipher-aes/aes-runtime-execution']
CRYPTO['ghash-runtime-execution'] = ['hazmat-ghash', 'brynja-universal-hash-ghash/ghash-runtime-execution', 'dep:brynja-crypto-cpu',
                                     'brynja-crypto-cpu/ghash-runtime-execution']
MODE = ['dep:brynja-core', 'dep:brynja-cipher-aes', 'brynja-cipher-aes/__mode',
        'dep:brynja-universal-hash-ghash', 'brynja-universal-hash-ghash/__mode']
PAIRED = ['dep:brynja-crypto-cpu', 'brynja-crypto-cpu/aes-static-execution',
          'brynja-crypto-cpu/ghash-runtime-execution', 'brynja-cipher-aes/__mode-execution',
          'brynja-universal-hash-ghash/__mode-execution']
FEATURES = {
    'brynja-aead-gcm': {'aes-gcm': MODE, 'gmac': MODE, 'aes-gcm-execution': ['aes-gcm', *PAIRED],
                        'gmac-execution': ['gmac', *PAIRED]},
    'brynja-universal-hash-ghash': {
        '__mode': ['dep:brynja-core'],
        '__mode-execution': ['__mode', 'dep:brynja-crypto-cpu', 'brynja-crypto-cpu/ghash-runtime-execution'],
        'hazmat-ghash': ['dep:brynja-core'],
        'ghash-runtime-execution': ['hazmat-ghash', 'dep:brynja-crypto-cpu', 'brynja-crypto-cpu/ghash-runtime-execution'],
        'cpu': ['dep:brynja-crypto-cpu'],
    },
    'brynja-cipher-aes': {
        '__mode': ['dep:brynja-core'],
        '__mode-execution': ['__mode', 'dep:brynja-crypto-cpu', 'brynja-crypto-cpu/aes-static-execution'],
        'hazmat-aes-block': ['dep:brynja-core'],
        'external-key-provider': ['dep:brynja-core'],
        'aes-static-execution': ['hazmat-aes-block', 'dep:brynja-crypto-cpu', 'brynja-crypto-cpu/aes-static-execution'],
        'aes-runtime-execution': ['aes-static-execution', 'brynja-crypto-cpu/aes-runtime-execution'],
    },
    'brynja-crypto': {**CRYPTO, 'poly1305': ['dep:brynja-mac-poly1305'],
                     'chacha20poly1305-x86': ['chacha20poly1305', 'brynja-aead-chacha20poly1305/chacha20poly1305-x86'],
                     'chacha20poly1305-neon': ['chacha20poly1305', 'brynja-aead-chacha20poly1305/chacha20poly1305-neon'],
                     'chacha20poly1305': ['dep:brynja-aead-chacha20poly1305'],
                     'hazmat-chacha20': ['dep:brynja-cipher-chacha', 'brynja-cipher-chacha/hazmat-chacha20']},
    'brynja': {feature: ['brynja-crypto/' + feature] for feature in (*CRYPTO, 'hazmat-chacha20', 'poly1305', 'chacha20poly1305', 'chacha20poly1305-x86', 'chacha20poly1305-neon')},
    'brynja-aead-chacha20poly1305': {'chacha20poly1305-neon': ['brynja-cipher-chacha/chacha20-neon', 'brynja-mac-poly1305/poly1305-neon'], 'chacha20poly1305-x86': ['brynja-cipher-chacha/chacha20-sse2', 'brynja-mac-poly1305/poly1305-avx2']},
}
FEATURES['brynja']['ghash-runtime-execution'] = ['hazmat-ghash',
                                                'brynja-crypto/ghash-runtime-execution']


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
    # The standalone stream's SSE2 feature is not forwarded by the facade.
    protocol_edges[names['brynja-cipher-chacha']].discard(names['brynja-crypto-cpu'])
    protocol_edges[names['brynja-cipher-aes']].discard(names['brynja-crypto-cpu'])
    protocol_edges[names['brynja-aead-gcm']].discard(names['brynja-crypto-cpu'])
    protocol_edges[names['brynja-universal-hash-ghash']].discard(names['brynja-crypto-cpu'])
    for engine in ('brynja-tls', 'brynja-tls12', 'brynja-tls13',
                   'brynja-tls13-handshake', 'brynja-dtls', 'brynja-quic-tls'):
        reached = reachable(engine, names, packages, protocol_edges)
        if {'brynja-crypto-cpu', 'brynja-crypto-cpu-std'}.intersection(reached):
            raise ValueError(f'protocol engine reaches a CPU adapter: {engine}')


def regressions(baseline, package, reject):
    count = 0
    for mode in ('aes-gcm-execution', 'gmac-execution'):
        for capability in ('aes-static-execution', 'ghash-runtime-execution'):
            changed = copy.deepcopy(baseline)
            package(changed, 'brynja-aead-gcm')['features'][mode].remove('brynja-crypto-cpu/' + capability)
            reject(changed, 'all-features', 'feature policy differs', 'reliance on transitive CPU features')
            count += 1
    for name, features in FEATURES.items():
        for feature in features:
            for replacement in ([], ['brynja-mac-kmac/conformance-testing']):
                if replacement == features[feature]:
                    continue  # An explicitly empty leaf feature is not a missing edge.
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
