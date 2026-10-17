"""ParallelHash facade/explicit threaded-adapter archive acceptance, not qualification."""
import importlib.util
import json
from pathlib import Path
import re
import sys
from unittest.mock import patch

import facade_parallelhash_cases as lifecycle
import facade_parallelhash_probes as probes
import facade_sha2_routes as routes
from facade_keccak_cases import require_runtime_rejection

ROOT = Path(__file__).resolve().parents[2]
FEATURES = ['parallelhash-hardened-batch']
ARCHIVE = ('brynja-hash-parallel-std', '0.1.0', ('src/lib.rs', 'src/execution/batch.rs'))
HOST = ('host = { package="brynja-crypto-cpu-std", version="=0.1.1", '
        'default-features=false, features=["keccak-hardened-batch"] }\n'
        'threads = { package="brynja-hash-parallel-std", version="=0.1.0", '
        'default-features=false, features=["runtime-batch-execution"] }\n')
INVALID = (
    ('parallel128 0 - 0 - 0 8', 'field bound'),
    ('unknown 0 - 0 - 1 8', 'unknown identity'),
    ('parallel128 0 - 0 - 1 4096', 'field bound'),
    ('parallel128 0 - 8 - 1 8', 'bit length mismatch'),
    ('parallel128 0 - 0 - 1025 8', 'field bound'),
    ('parallel128 0 - 0 - 1 8 extra', 'field count'),
)


def require(condition, message):
    if not condition:
        raise ValueError('facade ParallelHash: ' + message)


def package_roots(packaging, root):
    # Extend only this consumer's archive population, not shared SHA-2 acceptance
    # or historical evidence. All copies still pass the original package helper.
    require(ARCHIVE[0] not in {name for name, *_ in packaging.PACKAGING_PACKAGES}, 'duplicate adapter')
    with patch.object(packaging, 'PACKAGING_PACKAGES', (*packaging.PACKAGING_PACKAGES, ARCHIVE)):
        return packaging.package_roots(root)


def corpus():
    path = ROOT / 'scripts/parallelhash/check-parallelhash-differential.py'
    spec = importlib.util.spec_from_file_location('facade_parallel_oracle', path)
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    # NIST short uncustomized samples, also recorded in the leaf official tests.
    short = bytes(base + offset for base in (0, 16, 32) for offset in range(8))
    for rate, bits, expected in (
        (168, 256, 'ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454a2b4f5'),
        (136, 512, 'bc1ef124da34495e948ead207dd9842235da432d2bbc54b4c110e64c451105531b7'
                   'f2a3e0ce055c02805e7c2de1fb746af97a1dd01f43b824e31b87612410429'),
    ):
        require(oracle.parallel_hash(rate, oracle.oracle.byte_bits(short), 8, [], bits, False).hex() == expected,
                'official ParallelHash oracle self-check')
    return render(oracle.cases())


def render(cases):
    counts = dict.fromkeys(('parallel128', 'parallel256', 'parallelxof128', 'parallelxof256'), 0)
    lines, answers, aligned = [], [], []
    for name, custom, cb, message, mb, block, ob, answer in cases:
        require(name in counts and len(answer) == (ob + 7) // 8 and
                (not ob % 8 or answer[-1] >> (ob % 8) == 0), 'oracle output/identity')
        require(block > 0 and len(message) == (mb + 7) // 8, 'oracle input/block')
        counts[name] += 1
        lines.append(f'{name} {cb} {custom.hex() or "-"} {mb} {message.hex() or "-"} {block} {ob}')
        answers.append(answer.hex())
        leaves = ((mb + 7) // 8 + block - 1) // block
        # Require intentionally rejects scalar tails; four aligns both AVX2 and NEON.
        if leaves and leaves % 4 == 0:
            aligned.append(len(lines) - 1)
    require(len(cases) == 256 and set(counts.values()) == {64}, 'oracle population')
    require(len(aligned) == 48 and {cases[i][0] for i in aligned} == set(counts), 'required corpus population')
    return lines, answers, aligned


def rewrite(text, package):
    require(package in ('brynja', 'brynja-crypto'), 'unknown facade')
    namespace = 'facade::crypto' if package == 'brynja' else 'facade'
    text = text.replace('brynja_hash_parallel_std', 'threads')
    text = text.replace('brynja_hash_parallel', namespace + '::parallelhash')
    text = text.replace('brynja_crypto_cpu_std', 'host')
    require(not re.search(r'\bbrynja_[a-z_]+\b', text), 'unexpected leaf dependency')
    return text


def probe_source():
    text = routes.PROBE
    return text[:text.index('    route!(sha256_batch,')] + '    route!(keccak_hardened_batch, "parallel");\n}\n'


def probe_result(output):
    lines = output.splitlines()
    require(len(lines) == 2 and lines[0] in ('CPU:avx2', 'CPU:neon', 'CPU:none') and
            lines[1] in ('ROUTE:parallel:true', 'ROUTE:parallel:false'), 'probe population/route')
    return lines[0][4:], lines[1].endswith(':true')


def install(api, consumer, roots, package):
    (consumer / 'src/bin').mkdir(parents=True, exist_ok=True)
    api.manifest(consumer, roots, package, FEATURES, extra=HOST)
    api.source(consumer, package, lifecycle.RUST)
    source = ROOT / 'assurance/parallelhash-batch-oracle/src'
    # Only this fixture's public threaded main/request are reused. The separate
    # local fixture imports deliberately hidden leaf-only hardened_in_place APIs.
    for name in ('main.rs', 'request.rs'):
        text = rewrite((source / name).read_text(), package)
        (consumer / 'src' / name).write_text(('#![forbid(unsafe_code)]\n' if name == 'main.rs' else '') + text)
    (consumer / 'src/bin/route-probe.rs').write_text(probe_source())


def binary(env, profile):
    name = 'facade-consumer.exe' if sys.platform == 'win32' else 'facade-consumer'
    return Path(env['CARGO_TARGET_DIR']) / ('release' if profile else 'debug') / name


def check_result(result, expected, workers, vector):
    require(result.returncode == 0 and result.stdout.splitlines() == expected and expected, 'oracle output/population')
    match = re.fullmatch(r'PARALLELHASH_BATCH_ORACLE: cases=(\d+); vector_calls=(\d+); workers=(\d+); '
                         r'max_thread_width=(\d+); profiles=public,secret; cleanup=drop,scratch\n?', result.stderr)
    require(match is not None, 'completion marker')
    count, calls, width, actual = map(int, match.groups())
    require(count == len(expected) and (calls > 0) == vector and width == workers and actual == workers,
            'case/vector/thread accounting')


def check_failure(result, error):
    require(result.returncode == 1 and not result.stdout and result.stderr.strip() == 'Error: ' + json.dumps(error),
            'non-atomic or unexpected rejection: ' + result.stderr[-1000:])


def campaign(api, consumer, cargo, env, data, available):
    lines, answers, aligned = data
    for profile in ((), ('--release',)):
        result = api.run(cargo + ['test', '--offline', *profile, '--lib'], consumer, env)
        require('test result: ok. 2 passed; 0 failed; 0 ignored;' in result.stdout, 'lifecycle population')
        api.run(cargo + ['build', '--offline', *profile, '--bin', 'facade-consumer'], consumer, env)
        for mode in ('portable', 'prefer', 'required'):
            indices = aligned if mode == 'required' else range(len(lines))
            requests = '\n'.join(lines[i] for i in indices) + '\n'
            expected = [answers[i] for i in indices]
            for workers in (1, 3):
                command = [str(binary(env, profile)), mode, str(workers)]
                accepted = mode != 'required' or available
                result = api.run(command, consumer, env, data=requests, success=accepted)
                if not accepted:
                    check_failure(result, 'authority: Unavailable')
                    continue
                check_result(result, expected, workers, available and mode != 'portable')
                if mode == 'required':
                    check_failure(api.run(command, consumer, env,
                        data='parallel128 0 - 8 01 1 8\n', success=False),
                        'public: Batch(Hash(IneligibleWorkload))')
                for invalid, error in INVALID:
                    for prefix in ('', requests.splitlines()[0] + '\n'):
                        check_failure(api.run(command, consumer, env, data=prefix + invalid + '\n', success=False), error)
                print(f'PASS: facade ParallelHash: cases={len(expected)}; mode={mode}; workers={workers}; '
                      f'profile={"release" if profile else "debug"}; vector={available and mode != "portable"}', flush=True)


MUTANTS = (
    ('src/execution/batch.rs', 'let _ = clear_owned_region(output);', 'let _ = output;',
     'parallel_lifecycle::owned_failures_and_reuse'),
    ('src/execution/batch/in_place.rs', 'let _ = clear_owned_region(output);', 'let _ = output;',
     'parallel_lifecycle::scoped_failures_and_reuse'),
)


def cleanup_mutants(api, consumer, roots, cargo, env):
    for filename, before, after, name in MUTANTS:
        path = roots[ARCHIVE[0]] / filename
        original = path.read_text()
        require(original.count(before) == 1, 'cleanup mutation anchor')
        command = cargo + ['test', '--offline', '--release', '--lib', name]
        try:
            path.write_text(original.replace(before, after))
            api.run(command + ['--no-run'], consumer, env)
            result = api.run(command + ['--', '--exact'], consumer, env, success=False)
            require_runtime_rejection(result, name)
        finally:
            path.write_text(original)
    result = api.run(cargo + ['test', '--offline', '--release', '--lib'], consumer, env)
    require('test result: ok. 2 passed; 0 failed; 0 ignored;' in result.stdout, 'restored lifecycle population')
    print('PASS: ParallelHash: two compiled secret-output cleanup mutants rejected', flush=True)


BEHAVIOR_MUTANTS = (
    ('src/execution/batch/in_place.rs', 'brynja_core::copy_secret_region(output, secret.expose())',
     'Ok::<(), ()>(())', 'scoped public output/report/clearing mismatch'),
    ('src/execution/batch/worker.rs', 'vector_calls: report.vector_calls',
     'vector_calls: 0', 'leaf/group/thread/route accounting'),
)


def behavior_mutants(api, consumer, roots, cargo, env, data, native):
    lines, answers, _ = data
    request = '\n'.join(lines) + '\n'
    for index, (filename, before, after, error) in enumerate(BEHAVIOR_MUTANTS):
        if index == 1 and not native:
            continue
        mode = 'prefer' if native else 'portable'
        path = roots[ARCHIVE[0]] / filename
        original = path.read_text()
        require(original.count(before) == 1, 'behavior mutation anchor')
        command = [str(binary(env, True)), mode, '3']
        try:
            path.write_text(original.replace(before, after))
            api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
            check_failure(api.run(command, consumer, env, data=request, success=False), error)
        finally:
            path.write_text(original)
        api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
        check_result(api.run(command, consumer, env, data=request), answers, 3, native)
    print(f'PASS: ParallelHash: compiled public-copy/report mutants rejected; vector_requested={native}', flush=True)


def execute(api, root, roots, cargo, env, native=False):
    consumer = root / 'parallelhash-facade-consumer'
    env = dict(env, CARGO_TARGET_DIR=str(root / 'parallelhash-target'))
    data = corpus()
    for package in ('brynja-crypto', 'brynja'):
        install(api, consumer, roots, package)
        metadata = api.resolved_metadata(cargo, consumer, env, roots)
        api.graph(json.loads(metadata.stdout), FEATURES, hosted=True, threaded=True)
        probe = cargo + ['run', '--offline', '--bin', 'route-probe']
        cpu, available = probe_result(api.run(probe, consumer, env).stdout)
        campaign(api, consumer, cargo, env, data, available)
        probes.negatives(api, consumer, package, cargo, env)
        cleanup_mutants(api, consumer, roots, cargo, env)
        behavior_mutants(api, consumer, roots, cargo, env, data, available)
        if native:
            require(cpu in ('avx2', 'neon'), 'requested SIMD absent')
            accelerated = dict(env, RUSTFLAGS='-C target-feature=+' + cpu,
                               CARGO_TARGET_DIR=str(root / 'parallelhash-native-target'))
            _, available = probe_result(api.run(probe, consumer, accelerated).stdout)
            require(available, 'requested SIMD unavailable')
            campaign(api, consumer, cargo, accelerated, data, available)
            behavior_mutants(api, consumer, roots, cargo, accelerated, data, True)
        print(f'PASS: {package}: threaded ParallelHash batch acceptance; native_requested={native}', flush=True)
