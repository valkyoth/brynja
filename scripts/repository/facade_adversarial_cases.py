"""Real downstream conformance-unification and protocol-isolation regressions."""
import json
import facade_conformance_cases
import facade_cshake_cases


PROTOCOLS = ('brynja-tls', 'brynja-tls12', 'brynja-tls13',
             'brynja-tls13-handshake', 'brynja-dtls', 'brynja-quic-tls')
CONFORMANCE = ('kmac128_conformance', 'kmac256_conformance',
               'kmac128_bits_conformance', 'kmac256_bits_conformance',
               'kmacxof128_public_conformance', 'kmacxof128_secret_conformance',
               'kmacxof256_public_conformance', 'kmacxof256_secret_conformance')
FIXED_METHODS = ('new_conformance', 'new_bits_conformance', 'finalize_tag_conformance',
                 'finalize_tag_bits_conformance', 'finalize_secret_bits_conformance',
                 'verify_conformance', 'verify_bits_conformance')
XOF_METHODS = ('new_conformance', 'new_bits_conformance', 'finalize_xof_conformance',
               'finalize_bits_xof_conformance')


def portable_conformance_negatives(api, consumer, package, cargo, env):
    # Leaf conformance is already enabled by an independent dependency. Check
    # inherent methods through all aliases, not only namespace free functions.
    count = 0
    for prefix in ('leaf', 'api', 'api::kmac'):
        for name, methods in (('Kmac128', FIXED_METHODS), ('Kmac256', FIXED_METHODS),
                              ('KmacXof128', XOF_METHODS), ('KmacXof256', XOF_METHODS)):
            for method in methods:
                path = f'{prefix}::{name}::{method}'
                api.source(consumer, package, f'pub fn probe() {{ let _ = {path}; }}\n')
                result = api.run(cargo + ['check', '--offline', '--message-format=json'],
                                 consumer, env, success=False)
                errors = [item['message'] for line in result.stdout.splitlines()
                          if (item := json.loads(line)).get('reason') == 'compiler-message'
                          and item['message']['level'] == 'error']
                api.require(any((error.get('code') or {}).get('code') == 'E0599'
                                and method in error['message'] for error in errors),
                            'inherent rejection failed for wrong reason: ' + path)
                count += 1
    print(f'PASS: {package}: {count} portable inherent-method rejections under unification', flush=True)
    for name in ('Kmac128', 'Kmac256', 'KmacXof128', 'KmacXof256',
                 'KmacXof128Reader', 'KmacXof256Reader'):
        probes = [f'pub fn probe(value: leaf::conformance::{name}) -> leaf::{name} '
                  '{ value.into() }\n']
        probes += [f'fn require<T: {bound}>() {{}}\n'
                   f'pub fn probe() {{ require::<leaf::conformance::{name}>(); }}\n'
                   for bound in ('Clone', 'Copy', 'core::fmt::Debug')]
        for body in probes:
            api.source(consumer, package, body)
            result = api.run(cargo + ['check', '--offline', '--message-format=json'],
                             consumer, env, success=False)
            api.require(any(item.get('reason') == 'compiler-message' and
                            (item['message'].get('code') or {}).get('code') == 'E0277'
                            for line in result.stdout.splitlines()
                            if (item := json.loads(line))),
                        'conformance ownership/conversion failed for wrong reason: ' + name)
    print(f'PASS: {package}: 24 conformance ownership/conversion rejections', flush=True)


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
    assert!(leaf::conformance::Kmac128::new_conformance(b"", b"").unwrap()
        .finalize_tag_conformance(&mut output).is_ok());
}
''' + facade_cshake_cases.CASES)
    for profile in ((), ('--release',)):
        api.test_run(cargo, consumer, env, 3, profile)
    # This deliberate negative fixture alone opts into leaf conformance. It is
    # not a production graph and does not relax graph()'s conformance rejection.
    api.resolved_metadata(cargo, consumer, env, roots)
    portable_conformance_negatives(api, consumer, package, cargo, env)
    facade_conformance_cases.check(api, consumer, package, cargo, env)
    probes = ['kmac::' + name for name in CONFORMANCE]
    probes += ['conformance', 'kmac::conformance']
    probes += ['kmac::execution::conformance', 'kmac::execution::in_place::conformance']
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
