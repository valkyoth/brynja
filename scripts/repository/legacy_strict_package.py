"""Separate Linux strict and Apple resident public legacy consumer profiles."""
import json
import platform
import re
import shlex
from unittest.mock import patch

import legacy_execution_package as shared
import legacy_strict_sources as cases
from facade_tuplehash_probes import diagnostic


def expected_features(family, resident=False):
    leaf = 'brynja-legacy-' + family
    features = {'facade-consumer': {'native'}, 'brynja-core': {'default'},
            'brynja-hash-core': {'default'}, 'brynja-crypto-cpu': {'default'},
            'brynja-hash-sha2': {'default', 'cpu'},
            'brynja-crypto-cpu-std': {'default', 'protected-memory'},
            leaf: {'default', 'cpu', 'hardened-execution', *(['batch'] if family == 'md5' else [])},
            leaf + '-std': {'strict-execution', 'strict-acceleration'}}
    if resident:
        for name in ('brynja-crypto-cpu', 'brynja-hash-sha2', 'brynja-crypto-cpu-std'):
            del features[name]
        features[leaf + '-std'] = {'macos-resident', 'macos-resident-acceleration'}
    return features


def graph(api, document, roots, consumer, family, resident=False):
    with patch.object(api.packaging, 'PACKAGING_PACKAGES', (*api.packaging.PACKAGING_PACKAGES, *shared.ARCHIVES)):
        api.archive_graph(document, roots, consumer)
    names = {p['id']: p['name'] for p in document['packages']}
    actual = {names[n['id']]: set(n['features']) for n in document['resolve']['nodes']}
    shared.require(actual == expected_features(family, resident), 'protected legacy exact feature closure: ' + repr(actual))


def install(consumer, roots, family, resident=False):
    (consumer / 'src/bin').mkdir(parents=True)
    (consumer / 'tests').mkdir()
    leaf = 'brynja-legacy-' + family
    feature = 'macos-resident-acceleration' if resident else 'strict-acceleration'
    manifest = ('[workspace]\n[package]\nname="facade-consumer"\nversion="0.0.0"\nedition="2024"\n'
                '[features]\nnative=[]\n[dependencies]\n'
                f'{leaf}={{version="=0.1.0",default-features=false}}\n'
                f'{leaf}-std={{version="=0.1.0",default-features=false,features=["{feature}"]}}\n'
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
    (consumer / 'tests/acceptance.rs').write_text(cases.source(family, resident))


def compiled_features(output, family):
    arch = re.findall(r'^target_arch="([^"]+)"$', output, re.M)
    shared.require(len(arch) == 1 and arch[0] in ('x86_64', 'aarch64'), 'protected consumer compiler architecture')
    features = set(re.findall(r'^target_feature="([^"]+)"$', output, re.M))
    required = {('x86_64', 'sha1'): {'sha', 'sse2'}, ('x86_64', 'md5'): {'avx2'},
                ('aarch64', 'sha1'): {'neon', 'sha2'}, ('aarch64', 'md5'): {'neon'}}
    return required[arch[0], family] <= features


def runtime_check(result, family, compiled, resident=False):
    shared.population(result, 4)
    prefix = 'RESIDENT_LEGACY_NATIVE:' if resident else 'STRICT_LEGACY_NATIVE:'
    marker = f'{prefix} {family}; ' + ('corpus=169' if family == 'sha1' else 'lanes=712')
    observed = [line for line in result.stdout.splitlines() if line.startswith(('STRICT_LEGACY_NATIVE:', 'RESIDENT_LEGACY_NATIVE:'))]
    shared.require(observed == ([marker] if compiled else []), 'strict route population')


def campaign(api, consumer, cargo, env, family, native, resident=False):
    cfg = api.run(['rustc', cargo[1], '--print', 'cfg', *shlex.split(env.get('RUSTFLAGS', ''))], consumer, env)
    compiled = compiled_features(cfg.stdout, family)
    shared.require(not native or compiled, 'requested native route not compiled')
    for profile in ([], ['--release']):
        command = cargo + ['test', '--offline', *profile, '--test', 'acceptance']
        if native:
            command += ['--features', 'native']
        result = api.run(command + ['--', '--nocapture', '--test-threads=1'], consumer, env)
        runtime_check(result, family, compiled, resident)
        print(f'PASS: {"resident" if resident else "strict"} legacy {family}; {profile or ["debug"]}; native={native}; public consumer', flush=True)


def negatives(api, consumer, cargo, env, family, resident=False):
    source = consumer / 'src/lib.rs'
    original = source.read_text()
    count = 0
    try:
        for owner in cases.owners(family):
            module = 'macos_resident' if resident else 'strict_execution'
            typename = f'brynja_legacy_{family}_std::{module}::{owner}'
            source.write_text(f'pub fn present(_:Option<{typename}>){{}}')
            api.run(cargo + ['check', '--offline', '--lib'], consumer, env)
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                source.write_text(f'fn bound<T:{bound}>(){{}} fn probe(){{bound::<{typename}>();}}')
                result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'], consumer, env, success=False)
                shared.require(diagnostic(result, 'E0277'), 'strict ownership diagnostic')
                count += 1
        for text, code in cases.negatives(family, resident):
            source.write_text(text)
            result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'], consumer, env, success=False)
            valid = diagnostic(result, code) if code else result.returncode == 101 and 'lifetime may not live long enough' in result.stdout
            shared.require(valid, 'strict lifetime/classification diagnostic')
            count += 1
    finally:
        source.write_text(original)
    shared.require(count == (22 if family == 'sha1' else 28), 'strict negative population')
    print(f'PASS: {"resident" if resident else "strict"} legacy {family}; {count} compiled ownership/lifetime/classification negatives', flush=True)


def mutants(api, consumer, roots, cargo, env, family, native, resident=False):
    selected = cases.mutations(family, native, resident)
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
    campaign(api, consumer, cargo, env, family, native, resident)
    print(f'PASS: {"resident" if resident else "strict"} legacy {family}; {len(selected)*2} compiled mutation runs rejected; native={native}', flush=True)


def require_host(resident):
    if resident:
        shared.require(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'requires native Apple Silicon macOS')
    else:
        shared.require(platform.system() == 'Linux' and platform.machine() in ('x86_64', 'aarch64')
                       and platform.libc_ver()[0] == 'glibc', 'requires supported native GNU/Linux')


def execute(api, root, toolchain, native=False, resident=False):
    require_host(resident)
    env = api.clean_environment(root)
    api.cargo_environment.check(root / 'package-workspace', env)
    packages = tuple(p for p in api.packaging.PACKAGING_PACKAGES if p[0] in shared.SUPPORT) + shared.ARCHIVES
    with patch.dict(api.os.environ, env, clear=True), patch.object(api.packaging, 'PACKAGING_PACKAGES', packages):
        roots = api.packaging.package_roots(root)
    cargo = ['cargo', '+' + toolchain]
    for family in ('sha1', 'md5'):
        consumer = root / (family + '-protected-consumer')
        install(consumer, roots, family, resident)
        generic = dict(env, CARGO_TARGET_DIR=str(root / (family + '-strict-target')))
        metadata = api.run(cargo + ['metadata', '--offline', '--all-features', '--format-version=1'], consumer, generic)
        graph(api, json.loads(metadata.stdout), roots, consumer, family, resident)
        campaign(api, consumer, cargo, generic, family, False, resident)
        negatives(api, consumer, cargo, generic, family, resident)
        mutants(api, consumer, roots, cargo, generic, family, False, resident)
        if native:
            probe = api.run(cargo + ['run', '--offline', '--bin', 'probe'], consumer, generic)
            accelerated = dict(generic, RUSTFLAGS='-C target-feature=' + shared.native_flags(probe.stdout, family),
                               CARGO_TARGET_DIR=str(root / (family + '-strict-native-target')))
            campaign(api, consumer, cargo, accelerated, family, True, resident)
            mutants(api, consumer, roots, cargo, accelerated, family, True, resident)
    label = 'macOS resident (no dump exclusion)' if resident else 'Linux strict'
    print(f'Isolated {label} legacy consumer acceptance: PASS; not platform/native qualification', flush=True)
