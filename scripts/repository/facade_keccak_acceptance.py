"""Extracted facade hosted/static Keccak batches; no new qualification claim."""
import json
from pathlib import Path
import re
import sys

import facade_keccak_cases as oracle
import facade_keccak_routes as routes
import facade_sha2_routes as sha2_routes

ROOT = Path(__file__).resolve().parents[2]
FEATURES = ['keccak-batch', 'keccak-hardened-batch']
FAMILIES = {'keccak-batch': ('benchmark.rs', 'KECCAK_BATCH_ACCEPTANCE'),
            'hardened-keccak-batch': ('request.rs', 'HARDENED_KECCAK_BATCH')}
HOST = ('host = { package="brynja-crypto-cpu-std", version="=0.2.0", '
        'default-features=false, features=["keccak-batch", "keccak-hardened-batch"] }\n')


def require(condition, message):
    if not condition:
        raise ValueError('facade Keccak routes: ' + message)


def rewrite(text, package):
    require(package in ('brynja', 'brynja-crypto'), 'unknown facade')
    namespace = 'facade::crypto::sha3' if package == 'brynja' else 'facade::sha3'
    text = text.replace('brynja_hash_sha3', namespace).replace('brynja_crypto_cpu_std', 'host')
    require(not re.search(r'\bbrynja_[a-z_]+\b', text), 'unexpected fixture dependency')
    return text


def probe_source():
    text = sha2_routes.PROBE
    start = text.index('    route!(sha256_batch,')
    return text[:start] + ('    route!(keccak_batch, "keccak-batch");\n'
                           '    route!(keccak_hardened_batch, "hardened-keccak-batch");\n}\n')


def probe_result(output):
    lines = output.splitlines()
    require(len(lines) == 3 and lines[0] in ('CPU:avx2', 'CPU:neon', 'CPU:none'), 'probe population/CPU')
    result = {}
    for line in lines[1:]:
        fields = line.split(':')
        require(len(fields) == 3 and fields[0] == 'ROUTE' and fields[1] in FAMILIES
                and fields[1] not in result and fields[2] in ('true', 'false'), 'probe identity')
        result[fields[1]] = fields[2] == 'true'
    require(set(result) == set(FAMILIES), 'missing route')
    return lines[0][4:], result


def install(api, consumer, roots, package, data):
    (consumer / 'src/bin').mkdir(parents=True, exist_ok=True)
    api.manifest(consumer, roots, package, FEATURES, extra=HOST)
    api.source(consumer, package, routes.source())
    oracle.install(consumer, data)
    (consumer / 'src/bin/route-probe.rs').write_text(probe_source())
    for name, (support, _) in FAMILIES.items():
        src = ROOT / 'assurance' / name / 'src'
        files = list(src.rglob('*.rs'))
        require({p.name for p in files} == {'main.rs', support} and
                all(p.parent == src for p in files), 'fixture source population')
        destination = consumer / 'src/bin' / name
        destination.mkdir(exist_ok=True)
        for path in files:
            text = rewrite(path.read_text(), package)
            if path.name == 'main.rs':
                text = '#![forbid(unsafe_code)]\n' + text
            (destination / path.name).write_text(text)


def check_result(result, expected, marker, vector):
    require(result.returncode == 0 and result.stdout.splitlines() == expected, 'oracle mismatch')
    matches = re.findall(r'^' + marker + r': batches=(\d+); vector_calls=(\d+)(.*)$', result.stderr, re.M)
    require(len(matches) == 1, 'completion marker population')
    count, calls, suffix = matches[0]
    require(int(count) == len(expected) and (int(calls) > 0) == vector, 'count/route mismatch')
    require(suffix == ('; profiles=secret,declassified,public; cleanup=drop,declassify,staging'
                      if marker.startswith('HARDENED') else ''), 'profile/cleanup mismatch')


def check_unavailable(result):
    require(result.returncode == 1 and not result.stdout and
            result.stderr.strip() == 'Error: "authority: Unavailable"', 'unavailable did not reject before output')


def binary(consumer, env, profile, name):
    path = Path(env['CARGO_TARGET_DIR']) / ('release' if profile else 'debug') / name
    return path.with_suffix('.exe') if sys.platform == 'win32' else path


def campaign(api, consumer, cargo, env, data, selected):
    requests, answers = data
    expected = answers.splitlines()
    for profile in ((), ('--release',)):
        result = api.run(cargo + ['test', '--offline', *profile, '--lib'], consumer, env)
        require('test result: ok. 4 passed; 0 failed; 0 ignored;' in result.stdout, 'lifecycle population')
        for name, (_, marker) in FAMILIES.items():
            api.run(cargo + ['build', '--offline', *profile, '--bin', name], consumer, env)
            for mode in ('portable', 'prefer', 'required'):
                available = mode != 'required' or selected[name]
                result = api.run([str(binary(consumer, env, profile, name)), mode],
                                 consumer, env, data=requests, success=available)
                if available:
                    check_result(result, expected, marker, mode != 'portable' and selected[name])
                else:
                    check_unavailable(result)
            print(f'PASS: {name}: 256 independent batches; profile={"release" if profile else "debug"}; '
                  f'accelerated={selected[name]}', flush=True)


# Each no-op must fail the independent output or cleanup assertion. Ordinary
# scalar substitution instead preserves the digest and must fail the separate
# public session-counter witness; a self-reported vector count is insufficient.
MUTANTS = (
    ('batch/engine.rs',
     'session\n        .permute(PublicData::new(&mut workspace.vector))\n        .map_err(Error::Backend)?;',
     'let _ = &mut workspace.vector;', 'keccak_facade::ordinary_oracle'),
    ('batch/engine.rs',
     'session\n        .permute(PublicData::new(&mut workspace.vector))\n        .map_err(Error::Backend)?;',
     'for state in workspace.vector.iter_mut().take(width) { crate::keccak::permute(state); }',
     'keccak_counters::static_instruction_counter_and_revocation'),
    ('batch/engine.rs', 'report.vector_calls.checked_add(1)', 'report.vector_calls.checked_add(0)',
     'keccak_facade::ordinary_oracle'),
    ('hardened_batch/engine.rs',
     'session\n        .permute_bytes(&mut s.vector, &mut s.cpu)\n        .map_err(Error::Backend)?;',
     'let _ = (&mut s.vector, &mut s.cpu);', 'keccak_facade::secret_oracle'),
    ('hardened_batch/engine.rs', 'report.vector_calls.checked_add(1)', 'report.vector_calls.checked_add(0)',
     'keccak_facade::secret_oracle'),
    ('hardened_batch/output.rs', 'let _ = clear_owned_region(destination);', 'let _ = destination;',
     'keccak_facade::secret_oracle'),
)


def mutants(api, consumer, roots, cargo, env):
    for relative, before, after, test in MUTANTS:
        path = roots['brynja-hash-sha3'] / 'src' / relative
        original = path.read_text()
        require(original.count(before) == 1, 'mutation anchor: ' + relative)
        command = cargo + ['test', '--offline', '--release', '--lib', test]
        try:
            path.write_text(original.replace(before, after))
            api.run(command + ['--no-run'], consumer, env)
            result = api.run(command + ['--', '--exact', '--test-threads=1'], consumer, env, success=False)
            oracle.require_runtime_rejection(result, test)
        finally:
            path.write_text(original)
    result = api.run(cargo + ['test', '--offline', '--release', '--lib'], consumer, env)
    require('test result: ok. 4 passed; 0 failed; 0 ignored;' in result.stdout, 'restored lifecycle population')
    print('PASS: facade Keccak: six compiled SIMD/output/report/cleanup mutants rejected', flush=True)


def execute(api, root, roots, cargo, env, native=False):
    consumer = root / 'keccak-route-consumer'
    data = oracle.corpus()
    for package in ('brynja-crypto', 'brynja'):
        install(api, consumer, roots, package, data)
        metadata = api.resolved_metadata(cargo, consumer, env, roots)
        api.graph(json.loads(metadata.stdout), FEATURES, hosted=True)
        probe = cargo + ['run', '--offline', '--bin', 'route-probe']
        cpu, selected = probe_result(api.run(probe, consumer, env).stdout)
        campaign(api, consumer, cargo, env, data, selected)
        if native:
            require(cpu in ('avx2', 'neon'), 'requested SIMD absent')
            accelerated = dict(env, RUSTFLAGS='-C target-feature=+' + cpu,
                               CARGO_TARGET_DIR=str(root / 'keccak-native-target'))
            _, available = probe_result(api.run(probe, consumer, accelerated).stdout)
            require(all(available.values()), 'requested native routes unavailable')
            campaign(api, consumer, cargo, accelerated, data, available)
            mutants(api, consumer, roots, cargo, accelerated)
        print(f'PASS: {package}: hosted/static Keccak acceptance; native_requested={native}', flush=True)
