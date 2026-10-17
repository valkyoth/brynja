"""Archive-bound ordinary SHA-1/MD5 acceptance, isolated from modern facades."""
import importlib.util
import json
from pathlib import Path
import re
import sys
from unittest.mock import patch

import legacy_execution_cases as cases
from facade_tuplehash_probes import diagnostic

ROOT = Path(__file__).resolve().parents[2]
ARCHIVES = tuple((f'brynja-legacy-{family}{suffix}', '0.1.0', ('src/lib.rs',))
                 for family in ('sha1', 'md5') for suffix in ('', '-std'))
SUPPORT = {'brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu', 'brynja-crypto-cpu-std',
           'brynja-hash-sha2', 'brynja-hash-sha3', 'brynja-mac-kmac', 'brynja-hash-tuple'}


def require(value, message):
    if not value:
        raise ValueError('legacy execution package: ' + message)


def load(relative):
    spec = importlib.util.spec_from_file_location('legacy_' + Path(relative).stem.replace('-', '_'), ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def graph(api, document, roots, consumer, family):
    with patch.object(api.packaging, 'PACKAGING_PACKAGES', (*api.packaging.PACKAGING_PACKAGES, *ARCHIVES)):
        api.archive_graph(document, roots, consumer)
    leaf = 'brynja-legacy-' + family
    active = {p['id']: p['name'] for p in document['packages']}
    features = {active[n['id']]: set(n['features']) for n in document['resolve']['nodes']}
    require(set(features) == {'facade-consumer', 'brynja-core', 'brynja-hash-core', leaf, leaf + '-std'},
            'ordinary legacy enabled dependency closure')
    expected_leaf = {'default', 'cpu', 'execution'} | ({'batch'} if family == 'md5' else set())
    require(features[leaf] == expected_leaf and features[leaf + '-std'] == {'runtime-execution'},
            'ordinary legacy feature closure')
    require(features['facade-consumer'] == {'execution', 'runtime-execution'} and
            features['brynja-core'] == {'default'} and features['brynja-hash-core'] == {'default'},
            'hidden feature unification: ' + repr(features))


def population(result, count):
    summaries = re.findall(r'^test result: .*$', result.stdout, re.M)
    require(result.returncode == 0 and len(summaries) == 1 and
            summaries[0].startswith(f'test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'),
            'runtime population or skipped test')


def install(consumer, roots, family):
    leaf = 'brynja-legacy-' + family
    (consumer / 'src/bin').mkdir(parents=True)
    (consumer / 'tests/vectors').mkdir(parents=True)
    manifest = ('[workspace]\n[package]\nname="facade-consumer"\nversion="0.0.0"\nedition="2024"\n'
                '[features]\nexecution=[]\nruntime-execution=[]\n[dependencies]\n'
                f'{leaf}={{version="=0.1.0", default-features=false, features=["execution"]}}\n'
                f'{leaf}-std={{version="=0.1.0", default-features=false, features=["runtime-execution"]}}\n'
                '[patch.crates-io]\n')
    manifest += ''.join(f'{name}={{path={json.dumps(str(path))}}}\n' for name, path in roots.items())
    (consumer / 'Cargo.toml').write_text(manifest)
    (consumer / 'src/lib.rs').write_text('#![no_std]\n#![forbid(unsafe_code)]\n')
    (consumer / 'src/bin/probe.rs').write_text(cases.PROBE)
    for name, package in (('execution', leaf), ('hosted', leaf + '-std')):
        (consumer / f'tests/{name}.rs').write_bytes((roots[package] / 'tests/execution.rs').read_bytes())
    (consumer / 'tests/selection.rs').write_text(cases.selection(family))
    if family == 'sha1':
        (consumer / 'tests/vectors/nist.txt').write_bytes((roots[leaf] / 'tests/vectors/nist.txt').read_bytes())
        load('scripts/sha1/check-sha1-package.py').write_oracle(consumer / 'tests/oracle.rs')
    else:
        (consumer / 'src/main.rs').write_bytes((ROOT / 'assurance/md5-execution/src/main.rs').read_bytes())


def native_flags(output, family):
    match = re.fullmatch(r'CPU:(x86_64|aarch64|other):(true|false):(true|false)\n', output)
    require(match is not None, 'CPU probe population')
    arch, sha, md5 = match.groups()
    require(arch in ('x86_64', 'aarch64') and (sha if family == 'sha1' else md5) == 'true',
            'requested native bundle unavailable')
    return {('x86_64', 'sha1'): '+sha,+sse2', ('x86_64', 'md5'): '+avx2',
            ('aarch64', 'sha1'): '+neon,+sha2', ('aarch64', 'md5'): '+neon'}[arch, family]


def campaign(api, consumer, cargo, env, family, native):
    for profile in ([], ['--release']):
        for test, count in [('execution', 4 if family == 'sha1' else 3), ('hosted', 1), ('selection', 1),
                            *([('oracle', 1)] if family == 'sha1' else [])]:
            result = api.run(cargo + ['test', '--offline', '--all-features', *profile, '--test', test, '--', '--nocapture'], consumer, env)
            population(result, count)
            if test == 'selection' and native:
                require('LEGACY_SELECTION: static=true;' in result.stdout, 'native selection silently downgraded')
        if family == 'md5':
            api.run(cargo + ['build', '--offline', *profile, '--bin', 'facade-consumer'], consumer, env)
            binary = Path(env['CARGO_TARGET_DIR']) / ('release' if profile else 'debug') / ('facade-consumer.exe' if sys.platform == 'win32' else 'facade-consumer')
            oracle = load('scripts/md5/check-md5-execution-differential.py')
            # Hosted and compiled availability are distinct; probe each route,
            # then the oracle independently checks outputs and exact work counts.
            widths = {}
            for mode in ('portable', 'prefer', 'hosted'):
                result = api.run([str(binary), mode], consumer, env, data=('512:'+'00'*64+' ')*8+'\n')
                fields = result.stdout.split()
                require(len(fields) == 11 and fields[-3] in ('0', '4', '8'), 'MD5 route probe')
                widths[mode] = int(fields[-3])
                oracle.campaign(binary, mode, widths[mode])
            require(widths['portable'] == 0 and (not native or widths['prefer'] > 0), 'MD5 native route erased')
            if widths['prefer']:
                oracle.campaign(binary, 'require', widths['prefer'])
        print(f'PASS: isolated ordinary {family}: profile={"release" if profile else "debug"}; native_requested={native}', flush=True)


def negatives(api, consumer, cargo, env, family):
    path = consumer / 'src/lib.rs'
    original = path.read_text()
    count = 0
    try:
        for owner in ('Authority', 'Executor', *(["Stream<'static>"] if family == 'sha1' else [])):
            typename = f'brynja_legacy_{family}::execution::{owner}'
            path.write_text(f'pub fn present(_:Option<{typename}>) {{}}')
            api.run(cargo + ['check', '--offline', '--lib'], consumer, env)
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                path.write_text(f'fn bound<T:{bound}>() {{}} fn probe() {{bound::<{typename}>();}}')
                result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'], consumer, env, success=False)
                require(diagnostic(result, 'E0277'), 'wrong ownership rejection')
                count += 1
        for text, code in cases.misuses(family):
            path.write_text(text)
            result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'], consumer, env, success=False)
            require(diagnostic(result, code), 'wrong authority/classification rejection')
            count += 1
    finally:
        path.write_text(original)
    require(count == (18 if family == 'sha1' else 13), 'negative population')
    print(f'PASS: isolated {family}: {count} ownership/authority/classification rejections with type controls', flush=True)


def mutants(api, consumer, roots, cargo, env, family, native):
    for filename, before, after in cases.mutations(family, native):
        path = roots['brynja-legacy-' + family] / 'src' / filename
        original = path.read_text()
        require(original.count(before) == 1, 'mutation anchor: ' + filename)
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ['--release']):
                command = cargo + ['test', '--offline', '--all-features', *profile, '--test', 'execution', '--test', 'selection']
                api.run(command + ['--no-run'], consumer, env)
                result = api.run(command, consumer, env, success=False)
                require(result.returncode == 101 and 'test result: FAILED.' in result.stdout and
                        'panicked at' in result.stdout, 'mutant survived or unrelated failure')
        finally:
            path.write_text(original)
    # Repeat both public test populations after restoration, not just a build.
    for test, count in [('execution', 4 if family == 'sha1' else 3), ('selection', 1)]:
        population(api.run(cargo + ['test', '--offline', '--all-features', '--release', '--test', test], consumer, env), count)
    print(f'PASS: isolated {family}: {2 * len(cases.mutations(family, native))} compiled mutation runs rejected', flush=True)


def execute(api, root, toolchain, native=False):
    root.mkdir(parents=True, exist_ok=True)
    env = api.clean_environment(root)
    api.cargo_environment.check(root / 'package-workspace', env)
    packages = tuple(p for p in api.packaging.PACKAGING_PACKAGES if p[0] in SUPPORT) + ARCHIVES
    # This only changes the population of this isolated packaging invocation.
    # Existing native capture helpers and historical source bindings are untouched.
    with patch.dict(api.os.environ, env, clear=True), patch.object(api.packaging, 'PACKAGING_PACKAGES', packages):
        roots = api.packaging.package_roots(root)
    cargo = ['cargo', '+' + toolchain]
    for family in ('sha1', 'md5'):
        consumer = root / (family + '-consumer')
        install(consumer, roots, family)
        generic = dict(env, CARGO_TARGET_DIR=str(root / (family + '-target')))
        metadata = api.run(cargo + ['metadata', '--offline', '--all-features', '--format-version=1'], consumer, generic)
        graph(api, json.loads(metadata.stdout), roots, consumer, family)
        campaign(api, consumer, cargo, generic, family, False)
        negatives(api, consumer, cargo, generic, family)
        mutants(api, consumer, roots, cargo, generic, family, False)
        if native:
            probe = api.run(cargo + ['run', '--offline', '--bin', 'probe'], consumer, generic)
            accelerated = dict(generic, RUSTFLAGS='-C target-feature=' + native_flags(probe.stdout, family),
                               CARGO_TARGET_DIR=str(root / (family + '-native-target')))
            campaign(api, consumer, cargo, accelerated, family, True)
            mutants(api, consumer, roots, cargo, accelerated, family, True)
    print('Isolated ordinary legacy package acceptance: PASS; not native qualification', flush=True)
