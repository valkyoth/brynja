"""Optional native strict consumers: compiled admission is not runtime detection."""
import json
import re
import shlex
from unittest.mock import patch

import strict_public_consumer as scalar
import strict_accelerated_sources as sources
import strict_accelerated_mutants as mutants

require = scalar.shared.require


def expected_features():
    result = scalar.expected_features()
    result['brynja-strict'].add('acceleration')
    for name in ('brynja-crypto-cpu', 'brynja-hash-sha2', 'brynja-hash-sha3'):
        result[name].update(('static-execution', 'hardened-execution'))
    for name in ('brynja-mac-kmac', 'brynja-hash-tuple', 'brynja-hash-parallel'):
        result[name].add('hardened-execution')
    result['brynja-hash-parallel'].add('hardened-batch-execution')
    result['brynja-hash-parallel-std'].add('strict-acceleration')
    result['brynja-crypto-cpu-std'].update('strict-' + name + '-acceleration' for name in ('sha2', 'sha3', 'kmac', 'tuplehash'))
    return result


def graph(api, document, roots, consumer):
    with patch.object(api.packaging, 'PACKAGING_PACKAGES', (*api.packaging.PACKAGING_PACKAGES, *scalar.EXTRA)):
        api.archive_graph(document, roots, consumer)
    names = {p['id']: p['name'] for p in document['packages']}
    actual = {names[n['id']]: set(n['features']) for n in document['resolve']['nodes']}
    require(actual == expected_features(), 'strict accelerated exact feature closure: ' + repr(actual))


def probe(output):
    match = re.fullmatch(r'CPU:(x86_64|aarch64):(true|false):(true|false):(true|false)\n', output)
    require(match is not None, 'strict CPU probe population')
    arch, *values = match.groups()
    available = dict(zip(sources.ROUTES, (v == 'true' for v in values)))
    require(not available['wide'] or available['keccak'], 'contradictory wide CPU bundle')
    require(arch != 'aarch64' or available['wide'] == available['keccak'], 'contradictory Arm bundle')
    return arch, available


def flags(arch, available):
    require(any(available.values()), 'no requested native strict route available')
    if arch == 'x86_64':
        return ','.join((['+sha', '+sse2'] if available['narrow'] else []) +
                        (['+sha512'] if available['wide'] else []) +
                        (['+avx', '+avx2'] if available['wide'] or available['keccak'] else []))
    require(arch == 'aarch64', 'unsupported strict architecture')
    return ','.join(['+neon'] + (['+sha2'] if available['narrow'] else []) +
                    (['+sha3'] if available['wide'] or available['keccak'] else []))


def compiled(output):
    arch = re.findall(r'^target_arch="([^"]+)"$', output, re.M)
    require(len(arch) == 1 and arch[0] in ('x86_64', 'aarch64'), 'strict compiler architecture')
    features = set(re.findall(r'^target_feature="([^"]+)"$', output, re.M))
    required = ({'narrow': {'sha', 'sse2'}, 'wide': {'sha512', 'avx2', 'avx'}, 'keccak': {'avx', 'avx2'}}
                if arch[0] == 'x86_64' else {'narrow': {'neon', 'sha2'}, 'wide': {'neon', 'sha3'}, 'keccak': {'neon', 'sha3'}})
    return arch[0], {route: required[route] <= features for route in sources.ROUTES}


def admission_check(result, route, ready):
    scalar.shared.population(result, 1)
    markers = [line for line in result.stdout.splitlines() if line.startswith('STRICT_')]
    require(markers == [f'STRICT_COMPILED_ADMISSION: {route}; ready={str(ready).lower()}'], 'strict compiled admission population')


def runtime_check(result, route):
    scalar.shared.population(result, 5 if route == 'keccak' else 3)
    markers = [line for line in result.stdout.splitlines() if line.startswith('STRICT_')]
    require(sorted(markers) == sorted(sources.markers(route)), 'strict accelerated corpus population')


def campaign(api, consumer, cargo, env, route, ready):
    for profile in ([], ['--release']):
        command = cargo + ['test', '--locked', '--offline', *profile]
        # Compile every corpus even when this machine cannot execute its route.
        api.run(command + ['--test', 'acceptance', '--no-run'], consumer, env)
        result = api.run(command + ['--test', 'admission', '--', '--nocapture', '--test-threads=1'], consumer, env)
        admission_check(result, route, ready)
        if ready:
            result = api.run(command + ['--test', 'acceptance', '--', '--nocapture', '--test-threads=1'], consumer, env)
            runtime_check(result, route)
        print(f'PASS: strict compiled {route}; {profile or ["debug"]}; ' +
              ('corpus/lifecycle executed' if ready else 'MissingTargetFeatures rejection only; corpus NOT executed'), flush=True)


def execute(api, root, toolchain, native):
    scalar.legacy_strict_package.require_host(False)
    env = api.clean_environment(root)
    api.cargo_environment.check(root / 'package-workspace', env)
    names = set(scalar.expected_features()) - {'facade-consumer', 'brynja-strict', 'brynja-hash-parallel-std'}
    packages = tuple(p for p in api.packaging.PACKAGING_PACKAGES if p[0] in names) + scalar.EXTRA
    with patch.dict(api.os.environ, env, clear=True), patch.object(api.packaging, 'PACKAGING_PACKAGES', packages):
        roots = api.packaging.package_roots(root)
    cargo = ['cargo', '+' + toolchain]
    for route in sources.ROUTES:
        consumer = root / ('strict-' + route)
        scalar.install(consumer, roots)
        path = consumer / 'Cargo.toml'
        path.write_text(sources.once(path.read_text(), 'default-features=false}', 'default-features=false,features=["acceleration"]}'))
        sources.install(consumer, route)
        metadata = api.run(cargo + ['metadata', '--offline', '--format-version=1'], consumer, env)
        graph(api, json.loads(metadata.stdout), roots, consumer)
        detected_arch, available = probe(api.run(cargo + ['run', '--locked', '--offline', '--bin', 'cpu'], consumer, env).stdout)
        modes = [env]
        if native:
            modes.append(dict(env, RUSTFLAGS='-C target-feature=' + flags(detected_arch, available),
                              CARGO_TARGET_DIR=str(root / 'native-target')))
        for mode in modes:
            cfg = api.run(['rustc', cargo[1], '--print', 'cfg', *shlex.split(mode.get('RUSTFLAGS', ''))], consumer, mode)
            arch, ready = compiled(cfg.stdout)
            require(arch == detected_arch and all(not ready[r] or available[r] for r in sources.ROUTES), 'compiled strict route exceeds detected CPU/OS capability')
            if mode is not env:
                require(all(not available[r] or ready[r] for r in sources.ROUTES), 'native strict route not compiled')
            campaign(api, consumer, cargo, mode, route, ready[route])
            if ready[route]:
                mutants.run(api, consumer, roots, cargo, mode, route)
                campaign(api, consumer, cargo, mode, route, True)
        if route == 'narrow':
            scalar.negatives(api, consumer, cargo, env, compiled=True)
    print('Strict accelerated public consumer checks: PASS; unavailable routes and platform qualification remain separate', flush=True)
