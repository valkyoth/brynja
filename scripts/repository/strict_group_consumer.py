"""Strict-only protected group consumers with exact graphs and populations."""
import json
import shlex
from unittest.mock import patch

import strict_public_consumer as scalar
import strict_accelerated_consumer as accelerated
import strict_group_sources as sources
import strict_group_probes as probes

require = scalar.shared.require


def graph(api, document, roots, consumer):
    expected = accelerated.expected_features()
    expected['facade-consumer'] = {'native'}
    with patch.object(accelerated, 'expected_features', return_value=expected):
        accelerated.graph(api, document, roots, consumer)


def runtime_check(result, native):
    scalar.shared.population(result, 6)
    expected = [
        f'STRICT_GROUP_BATCH: scalar=662; SIMD={616 if native else 0}; ineligible={46 if native else 0}',
        f'STRICT_GROUP_PARALLEL: scalar=548; single={548 if native else 0}; SIMD={548 if native else 0}; workers=1,3',
        'STRICT_GROUP_BITS: named=240; general-t=4590; sparse scalar slots',
        f'STRICT_GROUP_MIXED: scalar=522; SIMD={522 if native else 0}; lanes={4192 if native else 2096}; general-t=510',
    ]
    actual = [s for s in result.stdout.splitlines() if s.startswith('STRICT_')]
    require(sorted(actual) == sorted(expected), 'strict group population/route changed: ' + repr(actual))


def campaign(api, consumer, cargo, env, native):
    for profile in ([], ['--release']):
        command = cargo + ['test', '--locked', '--offline', *profile, '--test', 'acceptance']
        if native:
            command += ['--features', 'native']
        result = api.run(command + ['--', '--nocapture', '--test-threads=1'], consumer, env)
        runtime_check(result, native)
        print(f'PASS: strict groups; {profile or ["debug"]}; native={native}; six corpus/lifecycle tests', flush=True)


def execute(api, root, toolchain, native):
    scalar.legacy_strict_package.require_host(False)
    env = api.clean_environment(root)
    api.cargo_environment.check(root / 'package-workspace', env)
    names = set(scalar.expected_features()) - {'facade-consumer', 'brynja-strict', 'brynja-hash-parallel-std'}
    packages = tuple(p for p in api.packaging.PACKAGING_PACKAGES if p[0] in names) + scalar.EXTRA
    with patch.dict(api.os.environ, env, clear=True), patch.object(api.packaging, 'PACKAGING_PACKAGES', packages):
        roots = api.packaging.package_roots(root)
    consumer = root / 'strict-group-consumer'
    sources.install(consumer, roots)
    cargo = ['cargo', '+' + toolchain]
    metadata = api.run(cargo + ['metadata', '--offline', '--features', 'native', '--format-version=1'], consumer, env)
    graph(api, json.loads(metadata.stdout), roots, consumer)
    arch, available = accelerated.probe(api.run(cargo + ['run', '--locked', '--offline', '--bin', 'cpu'], consumer, env).stdout)
    campaign(api, consumer, cargo, env, False)
    probes.negatives(api, consumer, cargo, env)
    probes.mutants(api, consumer, roots, cargo, env, False)
    campaign(api, consumer, cargo, env, False)
    if native:
        require(available['keccak'], 'native strict group requires complete root and SIMD CPU/OS bundles')
        mode = dict(env, RUSTFLAGS='-C target-feature=' + accelerated.flags(arch, available),
                    CARGO_TARGET_DIR=str(root / 'group-native-target'))
        cfg = api.run(['rustc', cargo[1], '--print', 'cfg', *shlex.split(mode['RUSTFLAGS'])], consumer, mode)
        actual_arch, ready = accelerated.compiled(cfg.stdout)
        require(actual_arch == arch and ready['keccak'] and all(not ready[r] or available[r] for r in available),
                'compiled group exceeds native capability')
        campaign(api, consumer, cargo, mode, True)
        probes.mutants(api, consumer, roots, cargo, mode, True)
        campaign(api, consumer, cargo, mode, True)
        probes.parallel_instrumented(api, roots, cargo, mode)
    print('Strict protected batch/ParallelHash public consumers: PASS; private erasure/platform qualification separate', flush=True)
