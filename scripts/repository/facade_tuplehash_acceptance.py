"""Independent TupleHash corpus and lifecycle tests through extracted facades."""
import importlib.util
import json
from pathlib import Path
import re
import sys

import facade_tuplehash_probes as probes
from facade_keccak_cases import require_runtime_rejection

ROOT = Path(__file__).resolve().parents[2]
FEATURES = ['tuplehash-runtime-execution']
HOST = ('host = { package="brynja-crypto-cpu-std", version="=0.2.0", '
        'default-features=false, features=["runtime-execution"] }\n')
SOURCES = {'main.rs', 'selection.rs', 'dispatch.rs', 'scoped_accelerated.rs'}
TESTS = {'scoped_accelerated.rs', 'scoped_accelerated/xof.rs'}
INVALID = (
    ('tuple128 1 80 8 0', 'noncanonical bit string'),
    ('tuplexof256 0 - 4096 0', 'length exceeds campaign limit'),
    ('unknown 0 - 8 0', None),
    ('tuple128 0 - 8 17', 'length exceeds campaign limit'),
    ('tuple128 0 - 8 0 trailing', 'too many fields'),
    ('tuple128 0 - 18446744073709551616 0', 'invalid length'),
    ('tuple128 0 - 8 1 1 80', 'noncanonical bit string'),
)


def require(condition, message):
    if not condition:
        raise ValueError('facade TupleHash: ' + message)


def corpus():
    directory = ROOT / 'scripts/tuplehash'
    sys.path.insert(0, str(directory))
    try:
        spec = importlib.util.spec_from_file_location('facade_tuple_oracle', directory / 'check-tuplehash-execution.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        oracle = module.oracle_module()
        oracle.verify_oracle()
        cases = module.official(oracle) + oracle.cases()
    finally:
        sys.path.pop(0)
    return render(cases)


def render(cases):
    counts = dict.fromkeys(('tuple128', 'tuple256', 'tuplexof128', 'tuplexof256'), 0)
    lines, answers = [], []
    for name, custom, cb, items, ob, answer in cases:
        require(name in counts and len(answer) == (ob + 7) // 8 and
                (not ob % 8 or answer[-1] >> (ob % 8) == 0), 'oracle identity/output shape')
        counts[name] += 1
        fields = [name, str(cb), custom.hex() or '-', str(ob), str(len(items))]
        for value, bits in items:
            fields.extend((str(bits), value.hex() or '-'))
        lines.append(' '.join(fields))
        answers.append(answer.hex())
    require(len(cases) == 268 and set(counts.values()) == {67}, 'oracle population')
    return '\n'.join(lines) + '\n', answers


def rewrite(text, package):
    require(package in ('brynja', 'brynja-crypto'), 'unknown facade')
    namespace = 'facade::crypto' if package == 'brynja' else 'facade'
    text = text.replace('brynja_crypto_cpu_std', 'host').replace('brynja_crypto_cpu', namespace + '::cpu')
    text = text.replace('brynja_hash_tuple', namespace + '::tuplehash')
    require(not re.search(r'\bbrynja_[a-z_]+\b', text), 'unexpected leaf dependency')
    return text


# Fixtures come from the reviewed repository; runtime dependencies remain extracted archives.
def install(api, consumer, roots, package):
    (consumer / 'src/bin').mkdir(parents=True, exist_ok=True)
    api.manifest(consumer, roots, package, FEATURES, extra=HOST)
    api.source(consumer, package, '')
    source = ROOT / 'assurance/tuplehash-execution'
    require({p.name for p in (source / 'src').rglob('*.rs')} == SOURCES and
            all(p.parent == source / 'src' for p in (source / 'src').rglob('*.rs')), 'fixture inventory')
    for filename in SOURCES:
        text = rewrite((source / 'src' / filename).read_text(), package)
        (consumer / 'src' / filename).write_text(('#![forbid(unsafe_code)]\n' if filename == 'main.rs' else '') + text)
    (consumer / 'src/bin/route-probe.rs').write_text(rewrite(probes.PROBE, package))
    for filename in TESTS:
        path = consumer / 'tests' / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('#![forbid(unsafe_code)]\n' + rewrite((source / 'tests' / filename).read_text(), package))
    # This is a consumer test switch, not a production/evidence cfg. Remove it
    # rather than enabling an extra Cargo feature in the downstream graph.
    text = (ROOT / 'crates/brynja-hash-tuple/tests/execution.rs').read_text()
    guard = '#![cfg(feature = "hardened-execution")]'
    require(text.count(guard) == 1, 'execution test feature guard')
    (consumer / 'tests/execution.rs').write_text(rewrite(text.replace(guard, '#![forbid(unsafe_code)]'), package))


def probe_result(output):
    lines = output.splitlines()
    require(len(lines) == 4 and lines[0] in ('CPU:avx2', 'CPU:arm-keccak', 'CPU:none'), 'CPU/probe population')
    require(lines[1] in ('KERNEL:X86Keccak', 'KERNEL:ArmKeccak'), 'kernel identity')
    require((lines[0] != 'CPU:avx2' or lines[1] == 'KERNEL:X86Keccak') and
            (lines[0] != 'CPU:arm-keccak' or lines[1] == 'KERNEL:ArmKeccak'), 'CPU/kernel mismatch')
    require(lines[2] in ('STATIC:ready', 'STATIC:WrongArchitecture', 'STATIC:MissingTargetFeatures'), 'static admission')
    require(lines[3] in ('HOSTED:ready', 'HOSTED:WrongArchitecture', 'HOSTED:MissingFeaturesOrOsState',
                         'HOSTED:MissingMigrationGuarantee'), 'hosted admission')
    return tuple(line.split(':', 1)[1] for line in lines)


def route(mode, kernel):
    return ('Portable' if mode in ('portable', 'prefer-portable') else
             f'Report {{ kernel: {kernel}, route: Accelerated, health: Some(Healthy) }}' if mode == 'hosted' else
             f'Report {{ kernel: {kernel}, health: Healthy, generation: 2 }}')


def check_result(result, expected, mode, kernel):
    require(len(expected) == 268 and result.returncode == 0 and result.stdout.splitlines() == expected,
            'independent output mismatch/population')
    require(result.stderr.strip() == 'TUPLEHASH_EXECUTION_ROUTE: ' + route(mode, kernel),
            'route identity/health/population: ' + result.stderr[-1500:])


def check_unavailable(result, reason, hosted):
    error = f'Unavailable({reason})' if hosted else reason
    expected = 'Error: Custom { kind: Other, error: "execution selection: ' + error + '" }'
    require(result.returncode == 1 and not result.stdout and result.stderr.strip() == expected,
            'unavailable must fail cleanly before output')


def check_failure(result, mode, kernel, kind, error):
    lines = result.stderr.splitlines()
    require(result.returncode == 1 and not result.stdout and len(lines) == 2 and
            lines[0] == 'TUPLEHASH_EXECUTION_ROUTE: ' + route(mode, kernel) and
            lines[1] == 'Error: Custom { kind: ' + kind + ', error: ' + json.dumps(error) + ' }',
            'unexpected/nonatomic rejection: ' + result.stderr[-1500:])


def binary(env, profile):
    name = 'facade-consumer.exe' if sys.platform == 'win32' else 'facade-consumer'
    return Path(env['CARGO_TARGET_DIR']) / ('release' if profile else 'debug') / name


def campaign(api, consumer, cargo, env, data, selected):
    _, kernel, static, hosted = selected
    requests, answers = data
    for profile in ((), ('--release',)):
        for test, count in (('execution', 6), ('scoped_accelerated', 7 if static == 'ready' else 1)):
            result = api.run(cargo + ['test', '--offline', *profile, '--test', test], consumer, env)
            require(f'test result: ok. {count} passed; 0 failed; 0 ignored;' in result.stdout, 'lifecycle population: ' + test)
        api.run(cargo + ['build', '--offline', *profile, '--bin', 'facade-consumer'], consumer, env)
        for mode in ('portable', 'prefer-portable', 'static', 'prefer', 'hosted'):
            reason = static if mode in ('static', 'prefer') else hosted if mode == 'hosted' else 'ready'
            command = [str(binary(env, profile)), mode]
            result = api.run(command, consumer, env, data=requests, success=reason == 'ready')
            if reason != 'ready':
                check_unavailable(result, reason, mode == 'hosted')
                continue
            check_result(result, answers, mode, kernel)
            for invalid, reason in INVALID:
                # A valid first case must not be partially printed if the next
                # request fails. Repeat malformed-only and mixed campaigns.
                for index, prefix in enumerate(('', requests.splitlines()[0] + '\n'), 1):
                    result = api.run(command, consumer, env, data=prefix + invalid + '\n', success=False)
                    kind = 'InvalidData' if reason else 'Other'
                    error = f'line {index}: {reason}' if reason else 'TupleHash execution: "unknown algorithm"'
                    check_failure(result, mode, kernel, kind, error)
            print(f'PASS: TupleHash: 268 independent cases; mode={mode}; '
                  f'profile={"release" if profile else "debug"}; kernel={kernel}', flush=True)


ALGORITHM_MUTANTS = (
    ('backend.rs', 'b"TupleHash"', 'b"WRONG"'),
    ('backend.rs', 'dispatch!(self, update(bytes))', 'let _ = (self, bytes); Ok(())'),
    ('core_state.rs', 'prefix.left(bits)', 'prefix.right(bits)'),
    ('core_state.rs', 'suffix.right(bits)', 'suffix.right(0)'),
)


def algorithm_mutants(api, consumer, roots, cargo, env, data, kernel):
    requests, answers = data
    for relative, before, after in ALGORITHM_MUTANTS:
        path = roots['brynja-hash-tuple'] / 'src/execution' / relative
        original = path.read_text()
        require(original.count(before) == 1, 'algorithm mutation anchor')
        try:
            path.write_text(original.replace(before, after))
            api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
            result = api.run([str(binary(env, True)), 'portable'], consumer, env, data=requests)
            require(result.stdout.splitlines() != answers, 'surviving compiled algorithm mutation')
        finally:
            path.write_text(original)
    api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
    check_result(api.run([str(binary(env, True)), 'portable'], consumer, env, data=requests), answers, 'portable', kernel)
    print('PASS: facade TupleHash: four compiled framing/domain/update mutants rejected', flush=True)


def cleanup_mutant(api, consumer, roots, cargo, env):
    path = roots['brynja-hash-tuple'] / 'src/execution/output.rs'
    original = path.read_text()
    before = 'let _ = clear_owned_region(self.0);'
    require(original.count(before) == 1, 'borrowed scratch mutation anchor')
    name = 'all_fixed_profiles_match_portable_for_bit_items_and_customization'
    command = cargo + ['test', '--offline', '--release', '--test', 'execution', name]
    try:
        path.write_text(original.replace(before, 'let _ = &self.0;'))
        api.run(command + ['--no-run'], consumer, env)
        result = api.run(command + ['--', '--exact'], consumer, env, success=False)
        require_runtime_rejection(result, name)
    finally:
        path.write_text(original)
    result = api.run(cargo + ['test', '--offline', '--release', '--test', 'execution'], consumer, env)
    require('test result: ok. 6 passed; 0 failed; 0 ignored;' in result.stdout, 'restored cleanup population')
    print('PASS: facade TupleHash: compiled borrowed-scratch cleanup mutant rejected', flush=True)


def fallback_mutant(api, consumer, roots, cargo, env, data, kernel):
    path = roots['brynja-hash-tuple'] / 'src/execution/backend.rs'
    original = path.read_text()
    before = 'Mode::Prefer(Some(session)) | Mode::Require(Some(session)) => Some(session),'
    require(original.count(before) == 1, 'scalar substitution anchor')
    try:
        path.write_text(original.replace(before,
            'Mode::Prefer(Some(session)) | Mode::Require(Some(session)) => { let _ = session; None },'))
        api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
        for mode in ('static', 'prefer'):
            result = api.run([str(binary(env, True)), mode], consumer, env, data=data[0], success=False)
            check_failure(result, mode, kernel, 'Other',
                          'execution selection: "actual tuple owner route differs from selected authority"')
    finally:
        path.write_text(original)
    api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
    for mode in ('static', 'prefer'):
        check_result(api.run([str(binary(env, True)), mode], consumer, env, data=data[0]), data[1], mode, kernel)
    print('PASS: facade TupleHash: compiled scalar substitution rejected in required/preferred modes', flush=True)


def execute(api, root, roots, cargo, env, native=False):
    consumer = root / 'tuplehash-facade-consumer'
    data = corpus()
    env = dict(env, CARGO_TARGET_DIR=str(root / 'tuplehash-target'))
    for package in ('brynja-crypto', 'brynja'):
        install(api, consumer, roots, package)
        metadata = api.resolved_metadata(cargo, consumer, env, roots)
        api.graph(json.loads(metadata.stdout), FEATURES, hosted=True)
        probe = cargo + ['run', '--offline', '--bin', 'route-probe']
        selected = probe_result(api.run(probe, consumer, env).stdout)
        campaign(api, consumer, cargo, env, data, selected)
        probes.negatives(api, consumer, package, cargo, env)
        algorithm_mutants(api, consumer, roots, cargo, env, data, selected[1])
        cleanup_mutant(api, consumer, roots, cargo, env)
        if native:
            require(selected[0] in ('avx2', 'arm-keccak'), 'requested native Keccak bundle absent')
            flags = '+avx2' if selected[0] == 'avx2' else '+neon,+sha2,+sha3'
            accelerated = dict(env, RUSTFLAGS='-C target-feature=' + flags,
                               CARGO_TARGET_DIR=str(root / 'tuplehash-native-target'))
            available = probe_result(api.run(probe, consumer, accelerated).stdout)
            require(available[2] == 'ready', 'required compiled TupleHash route unavailable')
            campaign(api, consumer, cargo, accelerated, data, available)
            fallback_mutant(api, consumer, roots, cargo, accelerated, data, available[1])
        print(f'PASS: {package}: TupleHash execution acceptance; native_requested={native}', flush=True)
