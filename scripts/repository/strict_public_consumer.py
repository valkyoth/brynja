"""Extracted strict-facade scalar acceptance, independent of workspace features.

Not accelerated, batch, platform-erasure or native-release qualification.
"""
import json
from unittest.mock import patch

import legacy_execution_package as shared
import legacy_strict_package
import strict_consumer_sources as cases
from facade_tuplehash_probes import diagnostic

EXTRA = tuple((name, '0.1.0', ('src/lib.rs',)) for name in
              ('brynja-hash-parallel-std', 'brynja-strict'))
MARKERS = ('STRICT_FAMILY_ORACLE: 662 passed', 'STRICT_KEYED_ORACLE: 512 passed; scalar',
           'STRICT_SHA2_BIT_ORACLE: 240 named; 4590 general-t; four input/output paths each')


def expected_features():
    return {
        'facade-consumer': set(), 'brynja-strict': set(),
        'brynja-core': {'default'}, 'brynja-hash-core': {'default'},
        'brynja-crypto-cpu': {'default', 'sha256-hardened-batch', 'sha512-hardened-batch', 'keccak-hardened-batch'},
        'brynja-hash-sha2': {'default', 'cpu', 'general-sha512-t', 'hardened-batch-execution', 'hardened-batch512-execution'},
        'brynja-hash-sha3': {'default', 'cpu', 'hardened-batch-execution'},
        'brynja-mac-kmac': {'default'}, 'brynja-hash-tuple': {'default'},
        'brynja-hash-parallel': {'default'}, 'brynja-hash-parallel-std': {'strict-execution'},
        'brynja-crypto-cpu-std': {'default', 'protected-memory', 'strict-sha2', 'strict-sha3',
            'strict-kmac', 'strict-tuplehash', 'strict-batch', 'sha256-hardened-batch',
            'sha512-hardened-batch', 'keccak-hardened-batch'},
    }


def graph(api, document, roots, consumer):
    with patch.object(api.packaging, 'PACKAGING_PACKAGES', (*api.packaging.PACKAGING_PACKAGES, *EXTRA)):
        api.archive_graph(document, roots, consumer)
    names = {p['id']: p['name'] for p in document['packages']}
    actual = {names[n['id']]: set(n['features']) for n in document['resolve']['nodes']}
    shared.require(actual == expected_features(), 'strict facade exact feature closure: ' + repr(actual))


def install(consumer, roots):
    (consumer / 'src').mkdir(parents=True)
    (consumer / 'tests').mkdir()
    manifest = ('[workspace]\n[package]\nname="facade-consumer"\nversion="0.0.0"\nedition="2024"\n'
                '[dependencies]\nbrynja-strict={version="=0.1.0",default-features=false}\n[patch.crates-io]\n')
    manifest += ''.join(f'{name}={{path={json.dumps(str(path))}}}\n' for name, path in roots.items())
    (consumer / 'Cargo.toml').write_text(manifest)
    (consumer / 'src/lib.rs').write_text('#![forbid(unsafe_code)]\n')
    cases.install(consumer, roots)


def runtime_check(result):
    shared.population(result, 7)
    observed = [line for line in result.stdout.splitlines() if line.startswith('STRICT_')]
    shared.require(sorted(observed) == sorted(MARKERS), 'strict scalar oracle population')


def campaign(api, consumer, cargo, env):
    for profile in ([], ['--release']):
        result = api.run(cargo + ['test', '--locked', '--offline', *profile, '--test', 'acceptance',
                                 '--', '--nocapture', '--test-threads=1'], consumer, env)
        runtime_check(result)
        print(f'PASS: strict facade; {profile or ["debug"]}; 6004 recorded/independent scalar cases; four lifecycle tests', flush=True)


def negatives(api, consumer, cargo, env):
    path = consumer / 'src/lib.rs'
    original = path.read_text()
    count = 0
    try:
        for family in ('sha2', 'sha3', 'kmac', 'tuplehash'):
            output = 'Digest' if family in ('sha2', 'sha3') else 'Output'
            for owner in ('Session', output + "<'static>"):
                name = f'brynja_strict::{family}::{owner}'
                path.write_text(f'pub fn present(_:Option<{name}>){{}}')
                api.run(cargo + ['check', '--locked', '--offline', '--lib'], consumer, env)
                for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                    path.write_text(f'fn bound<T:{bound}>(){{}} fn probe(){{bound::<{name}>();}}')
                    result = api.run(cargo + ['check', '--locked', '--offline', '--lib', '--message-format=json'],
                                     consumer, env, success=False)
                    shared.require(diagnostic(result, 'E0277'), 'strict public ownership diagnostic')
                    count += 1
            path.write_text(f'use brynja_strict::{family}::CompiledSession;')
            result = api.run(cargo + ['check', '--locked', '--offline', '--lib', '--message-format=json'],
                             consumer, env, success=False)
            shared.require(diagnostic(result, 'E0432'), 'strict default acceleration exposure')
            count += 1
            imports = f'use brynja_strict::{family}::{{Session,{output},Error}};\n'
            request = cases.request(family)
            positive = imports + f"fn loan(s:&mut Session)->Result<{output}<'_>,Error>{{s.{request}}}"
            path.write_text(positive)
            api.run(cargo + ['check', '--locked', '--offline', '--lib'], consumer, env)
            for body, code in (
                (positive.replace("<'_>", "<'static>"), None),
                (imports + f'fn reuse(s:&mut Session)->Result<(),Error>{{let first=s.{request}?; let _second=s.{request}?; let _=first.expose(); Ok(())}}', 'E0499'),
                (imports + f"fn public(loan:{output}<'_>){{let _=loan.declassify(&mut []);}}", 'E0061'),
            ):
                path.write_text(body)
                result = api.run(cargo + ['check', '--locked', '--offline', '--lib', '--message-format=json'],
                                 consumer, env, success=False)
                valid = diagnostic(result, code) if code else result.returncode == 101 and 'lifetime may not live long enough' in result.stdout
                shared.require(valid, 'strict public lifetime/classification diagnostic')
                count += 1
    finally:
        path.write_text(original)
    shared.require(count == 56, 'strict scalar negative population')
    print('PASS: strict facade; 56 ownership/lifetime/classification and default-acceleration negatives', flush=True)


def mutation_result(result, test):
    shared.require(result.returncode == 101 and f'test {test} ... FAILED' in result.stdout
                   and 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 6 filtered out;' in result.stdout
                   and 'panicked at' in result.stdout + result.stderr,
                   'strict mutation did not fail its exact runtime assertion')


def mutants(api, consumer, roots, cargo, env):
    selected = cases.mutations()
    for name, before, after, test in selected:
        path = roots['brynja-crypto-cpu-std'] / 'src' / name
        original = path.read_text()
        shared.require(original.count(before) == 1, 'strict mutation anchor: ' + name)
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ['--release']):
                command = cargo + ['test', '--locked', '--offline', *profile, '--test', 'acceptance']
                api.run(command + ['--no-run'], consumer, env)
                result = api.run(command + [test, '--', '--exact', '--nocapture'], consumer, env, success=False)
                mutation_result(result, test)
        finally:
            path.write_text(original)
    campaign(api, consumer, cargo, env)
    print(f'PASS: strict facade; {len(selected)*2} compiled budget/cancellation/output mutant runs rejected; restored source rerun', flush=True)


def execute(api, root, toolchain):
    legacy_strict_package.require_host(False)
    env = api.clean_environment(root)
    api.cargo_environment.check(root / 'package-workspace', env)
    names = set(expected_features()) - {'facade-consumer', 'brynja-strict', 'brynja-hash-parallel-std'}
    packages = tuple(p for p in api.packaging.PACKAGING_PACKAGES if p[0] in names) + EXTRA
    with patch.dict(api.os.environ, env, clear=True), patch.object(api.packaging, 'PACKAGING_PACKAGES', packages):
        roots = api.packaging.package_roots(root)
    consumer = root / 'strict-consumer'
    install(consumer, roots)
    cargo = ['cargo', '+' + toolchain]
    result = api.run(cargo + ['metadata', '--offline', '--format-version=1'], consumer, env)
    graph(api, json.loads(result.stdout), roots, consumer)
    campaign(api, consumer, cargo, env)
    negatives(api, consumer, cargo, env)
    mutants(api, consumer, roots, cargo, env)
    print('Strict facade scalar public consumer: PASS; acceleration/batching and platform qualification separate', flush=True)
