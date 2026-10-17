"""Real downstream conformance-unification and protocol-isolation regressions."""
import json


PROTOCOLS = ('brynja-tls', 'brynja-tls12', 'brynja-tls13',
             'brynja-tls13-handshake', 'brynja-dtls', 'brynja-quic-tls')
CONFORMANCE = ('kmac128_conformance', 'kmac256_conformance',
               'kmac128_bits_conformance', 'kmac256_bits_conformance',
               'kmacxof128_public_conformance', 'kmacxof128_secret_conformance',
               'kmacxof256_public_conformance', 'kmacxof256_secret_conformance')


def namespace_negatives(api, consumer, roots, package, cargo, env):
    extra = ('leaf = { package="brynja-mac-kmac", version="=0.1.0", '
             'default-features=false, features=["conformance-testing"] }\n')
    api.manifest(consumer, roots, package, list(api.cases.PROBES), extra=extra)
    api.source(consumer, package, '''
#[test]
fn direct_leaf_conformance_does_not_weaken_production_functions() {
    let mut output = [0; 4];
    assert!(leaf::kmac128_conformance(b"", b"msg", b"", &mut output).is_ok());
    assert!(api::kmac::kmac128(b"", b"msg", b"", &mut output).is_err());
    assert!(api::kmac128(b"", b"msg", b"", &mut output).is_err());
}
''')
    api.test_run(cargo, consumer, env, 1)
    # This deliberate negative fixture alone opts into leaf conformance. It is
    # not a production graph and does not relax graph()'s conformance rejection.
    api.resolved_metadata(cargo, consumer, env, roots)
    probes = ['kmac::' + name for name in CONFORMANCE]
    probes += [name + '::hardened_in_place' for name in
               ('sha2', 'sha3', 'kmac', 'tuplehash', 'parallelhash')]
    probes += ['sha3::HardenedCshake128Setup', 'sha3::HardenedCshake256Setup',
               'kmac::Kmac128Setup', 'kmac::Kmac256Setup']
    for path in probes:
        api.source(consumer, package, f'pub use api::{path} as Probe;\n')
        result = api.run(cargo + ['check', '--offline', '--message-format=json'],
                         consumer, env, success=False)
        messages = [json.loads(line) for line in result.stdout.splitlines()]
        api.require(any(item.get('reason') == 'compiler-message' and
                        (item['message'].get('code') or {}).get('code') == 'E0432'
                        for item in messages), 'namespace rejection failed for wrong reason: ' + path)
    print(f'PASS: {package}: {len(probes)} leaf-only namespace rejections under unification', flush=True)


def protocol_graph(document):
    # An isolated dependency closure, not workspace-wide unified metadata.
    # Do not remove or filter ANY dependency edge before checking it.
    names = {package['id']: package['name'] for package in document['packages']}
    active = {names[node['id']] for node in document['resolve']['nodes']}
    if {'brynja-crypto-cpu', 'brynja-crypto-cpu-std'}.intersection(active):
        raise ValueError('isolated protocol dependency reaches CPU code')


def protocols(api, consumer, roots, cargo, env, bare_target):
    for package in PROTOCOLS:
        api.manifest(consumer, roots, package, [])
        api.source(consumer, package, '')
        metadata = api.resolved_metadata(cargo, consumer, env, roots)
        protocol_graph(json.loads(metadata.stdout))
        api.run(cargo + ['check', '--offline', '--target', bare_target], consumer, env)
        # Mutate the real extracted engine, bypassing the repository's separate
        # manifest policy. This must still fail the unfiltered resolved check.
        owner = {'brynja-tls': 'brynja-tls12',
                 'brynja-quic-tls': 'brynja-tls13-handshake'}.get(package, package)
        manifest = roots[owner] / 'Cargo.toml'
        original = manifest.read_text()
        marker = '[dependencies.brynja-crypto]\n'
        api.require(original.count(marker) == 1, 'protocol crypto edge missing: ' + package)
        try:
            manifest.write_text(original.replace(marker, marker +
                                'features = ["cpu", "sha2-runtime-execution"]\n'))
            metadata = api.resolved_metadata(cargo, consumer, env, roots)
            try:
                protocol_graph(json.loads(metadata.stdout))
            except ValueError:
                pass
            else:
                raise AssertionError('protocol feature mutation was accepted: ' + package)
        finally:
            manifest.write_text(original)
    print('PASS: six isolated protocol closures and six real feature-activation mutants', flush=True)
