"""Isolated public GNU/Linux protected legacy consumers, not private erasure proof."""
import json
import platform
from unittest.mock import patch

import legacy_execution_package as shared
import legacy_strict_sources as cases
from facade_tuplehash_probes import diagnostic


def expected_features(family):
    leaf = 'brynja-legacy-' + family
    return {'facade-consumer': {'native'}, 'brynja-core': {'default'},
            'brynja-hash-core': {'default'}, 'brynja-crypto-cpu': {'default'},
            'brynja-hash-sha2': {'default', 'cpu'},
            'brynja-crypto-cpu-std': {'default', 'protected-memory'},
            leaf: {'default', 'cpu', 'hardened-execution', *(['batch'] if family == 'md5' else [])},
            leaf + '-std': {'strict-execution', 'strict-acceleration'}}


def graph(api, document, roots, consumer, family):
    with patch.object(api.packaging, 'PACKAGING_PACKAGES', (*api.packaging.PACKAGING_PACKAGES, *shared.ARCHIVES)):
        api.archive_graph(document, roots, consumer)
    names = {p['id']: p['name'] for p in document['packages']}
    actual = {names[n['id']]: set(n['features']) for n in document['resolve']['nodes']}
    shared.require(actual == expected_features(family), 'strict legacy exact feature closure: ' + repr(actual))


def install(consumer, roots, family):
    (consumer / 'src/bin').mkdir(parents=True)
    (consumer / 'tests').mkdir()
    leaf = 'brynja-legacy-' + family
    manifest = ('[workspace]\n[package]\nname="facade-consumer"\nversion="0.0.0"\nedition="2024"\n'
                '[features]\nnative=[]\n[dependencies]\n'
                f'{leaf}={{version="=0.1.0",default-features=false}}\n'
                f'{leaf}-std={{version="=0.1.0",default-features=false,features=["strict-acceleration"]}}\n'
                '[patch.crates-io]\n')
    manifest += ''.join(f'{name}={{path={json.dumps(str(path))}}}\n' for name, path in roots.items())
    (consumer / 'Cargo.toml').write_text(manifest)
    (consumer / 'src/lib.rs').write_text('#![forbid(unsafe_code)]\n')
    (consumer / 'src/bin/probe.rs').write_text(shared.cases.PROBE)
    # Reuse the reviewed independent corpus, not the resident API/source adapter.
    rows = shared.load('scripts/cryptography/macos_legacy_resident_oracle.py').corpus()
    shared.require(len(rows) == 169 and sum(int(r.split()[0]) >= 512 for r in rows) == 89,
                   'strict legacy independent corpus population')
    (consumer / 'tests/legacy.txt').write_text('\n'.join(rows) + '\n')
    (consumer / 'tests/acceptance.rs').write_text(cases.source(family))


def runtime_check(result, family, native, arch):
    shared.population(result, 4)
    marker = f'STRICT_LEGACY_NATIVE: {family}; ' + ('corpus=169' if family == 'sha1' else 'lanes=712')
    compiled = native or (family == 'md5' and arch == 'aarch64')
    observed = [line for line in result.stdout.splitlines() if line.startswith('STRICT_LEGACY_NATIVE:')]
    shared.require(observed == ([marker] if compiled else []), 'strict route population')


def campaign(api, consumer, cargo, env, family, native):
    for profile in ([], ['--release']):
        command = cargo + ['test', '--offline', *profile, '--test', 'acceptance']
        if native:
            command += ['--features', 'native']
        result = api.run(command + ['--', '--nocapture', '--test-threads=1'], consumer, env)
        runtime_check(result, family, native, platform.machine())
        print(f'PASS: strict legacy {family}; {profile or ["debug"]}; native={native}; public consumer', flush=True)


def negatives(api, consumer, cargo, env, family):
    source = consumer / 'src/lib.rs'
    original = source.read_text()
    count = 0
    try:
        for owner in cases.owners(family):
            typename = f'brynja_legacy_{family}_std::strict_execution::{owner}'
            source.write_text(f'pub fn present(_:Option<{typename}>){{}}')
            api.run(cargo + ['check', '--offline', '--lib'], consumer, env)
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                source.write_text(f'fn bound<T:{bound}>(){{}} fn probe(){{bound::<{typename}>();}}')
                result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'], consumer, env, success=False)
                shared.require(diagnostic(result, 'E0277'), 'strict ownership diagnostic')
                count += 1
        for text, code in cases.negatives(family):
            source.write_text(text)
            result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'], consumer, env, success=False)
            valid = diagnostic(result, code) if code else result.returncode == 101 and 'lifetime may not live long enough' in result.stdout
            shared.require(valid, 'strict lifetime/classification diagnostic')
            count += 1
    finally:
        source.write_text(original)
    shared.require(count == (22 if family == 'sha1' else 28), 'strict negative population')
    print(f'PASS: strict legacy {family}; {count} compiled ownership/lifetime/classification negatives', flush=True)


def mutants(api, consumer, roots, cargo, env, family, native):
    selected = cases.mutations(family, native)
    for name, before, after, test in selected:
        path = roots[f'brynja-legacy-{family}-std'] / 'src' / name
        original = path.read_text()
        shared.require(original.count(before) == 1, 'strict mutation anchor: ' + name)
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ['--release']):
                command = cargo + ['test', '--offline', *profile, '--test', 'acceptance']
                if native:
                    command += ['--features', 'native']
                api.run(command + ['--no-run'], consumer, env)
                result = api.run(command + [test, '--', '--exact', '--nocapture'], consumer, env, success=False)
                shared.require(result.returncode == 101 and 'test result: FAILED. 0 passed; 1 failed;' in result.stdout
                               and 'panicked at' in result.stdout + result.stderr,
                               'strict mutant unrelated failure: ' + name + '\n' + result.stdout[-3000:] + result.stderr[-1500:])
        finally:
            path.write_text(original)
    campaign(api, consumer, cargo, env, family, native)
    print(f'PASS: strict legacy {family}; {len(selected)*2} compiled mutation runs rejected; native={native}', flush=True)


def execute(api, root, toolchain, native=False):
    shared.require(platform.system() == 'Linux' and platform.machine() in ('x86_64', 'aarch64')
                   and platform.libc_ver()[0] == 'glibc', 'requires supported native GNU/Linux')
    env = api.clean_environment(root)
    api.cargo_environment.check(root / 'package-workspace', env)
    packages = tuple(p for p in api.packaging.PACKAGING_PACKAGES if p[0] in shared.SUPPORT) + shared.ARCHIVES
    with patch.dict(api.os.environ, env, clear=True), patch.object(api.packaging, 'PACKAGING_PACKAGES', packages):
        roots = api.packaging.package_roots(root)
    cargo = ['cargo', '+' + toolchain]
    for family in ('sha1', 'md5'):
        consumer = root / (family + '-strict-consumer')
        install(consumer, roots, family)
        generic = dict(env, CARGO_TARGET_DIR=str(root / (family + '-strict-target')))
        metadata = api.run(cargo + ['metadata', '--offline', '--all-features', '--format-version=1'], consumer, generic)
        graph(api, json.loads(metadata.stdout), roots, consumer, family)
        campaign(api, consumer, cargo, generic, family, False)
        negatives(api, consumer, cargo, generic, family)
        mutants(api, consumer, roots, cargo, generic, family, False)
        if native:
            probe = api.run(cargo + ['run', '--offline', '--bin', 'probe'], consumer, generic)
            accelerated = dict(generic, RUSTFLAGS='-C target-feature=' + shared.native_flags(probe.stdout, family),
                               CARGO_TARGET_DIR=str(root / (family + '-strict-native-target')))
            campaign(api, consumer, cargo, accelerated, family, True)
            mutants(api, consumer, roots, cargo, accelerated, family, True)
    print('Isolated Linux strict legacy consumer acceptance: PASS; not platform/native qualification', flush=True)
