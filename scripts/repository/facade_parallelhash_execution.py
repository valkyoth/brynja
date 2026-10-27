"""Extracted facade scheduled/streaming/scoped ParallelHash execution acceptance."""
import json
from pathlib import Path
import re

import facade_parallelhash_acceptance as batch
import facade_parallelhash_driver as driver
import facade_parallelhash_references as references
import facade_tuplehash_acceptance as selection
import facade_tuplehash_probes as probes
from facade_keccak_cases import require_runtime_rejection

ROOT = batch.ROOT
FEATURES = ['parallelhash-runtime-execution', 'sha3-hardened-execution']
HOST = ('host = { package="brynja-crypto-cpu-std", version="=0.2.0", '
        'default-features=false, features=["runtime-execution"] }\n'
        'threads = { package="brynja-hash-parallel-std", version="=0.1.0", '
        'default-features=false, features=["runtime-execution"] }\n')
SOURCES = ('execution.rs', 'scoped_execution.rs', 'scoped_accelerated.rs', 'scoped_scheduled_accelerated.rs')
MODES = ('portable', 'scheduled', 'prefer', 'required', 'static', 'stream',
         'stream-prefer', 'stream-required', 'stream-static', 'threads-portable',
         'threads-prefer', 'threads-required', 'threads-static')
SCOPED = {'static', 'stream-static', 'threads-static'}
TESTS = {'execution': 6, 'execution_stream': 5, 'threaded_execution': 4, 'threaded_scoped': 4}
SCOPED_FILES = {'scheduled.rs', 'scheduled_lifecycle.rs', 'xof.rs', 'xof_lifecycle.rs'}


def require(value, message):
    if not value:
        raise ValueError('facade ParallelHash execution: ' + message)


def rewrite(text, package):
    namespace = 'facade::crypto' if package == 'brynja' else 'facade'
    text = text.replace('brynja_crypto_cpu_std', 'host')
    text = text.replace('brynja_crypto_cpu', namespace + '::cpu')
    text = text.replace('brynja_hash_sha3', namespace + '::sha3')
    return batch.rewrite(text, package)


def test_source(text, package):
    # Consumer-only test guards, not a production feature/cfg bypass. The
    # extracted manifest explicitly enables every production API used below.
    guard = re.compile(r'^#!?\[cfg\(feature = "(?:hardened|runtime)-execution"\)\]\n', re.M)
    text, count = guard.subn('', text)
    require(count in (0, 1, 2), 'unexpected test guards')
    return '#![forbid(unsafe_code)]\n' + rewrite(text, package)


def install(api, consumer, roots, package):
    (consumer / 'src/bin').mkdir(parents=True, exist_ok=True)
    api.manifest(consumer, roots, package, FEATURES, extra=HOST)
    api.source(consumer, package, '')
    (consumer / 'src/main.rs').write_text(rewrite(driver.MAIN, package))
    (consumer / 'src/request.rs').write_text(rewrite(
        (ROOT / 'assurance/parallelhash-batch-oracle/src/request.rs').read_text(), package))
    source = ROOT / 'assurance/parallelhash-differential/src'
    for filename in SOURCES:
        (consumer / 'src' / filename).write_text(rewrite((source / filename).read_text(), package))
    (consumer / 'src/bin/route-probe.rs').write_text(rewrite(probes.PROBE, package))
    tests = consumer / 'tests'
    tests.mkdir(exist_ok=True)
    leaf = ROOT / 'crates/brynja-hash-parallel/tests'
    host = ROOT / 'crates' / batch.ARCHIVE[0] / 'tests'
    for target, path in (('execution', leaf / 'execution.rs'), ('execution_stream', leaf / 'execution_stream.rs'),
                         ('threaded_execution', host / 'execution.rs'), ('threaded_scoped', host / 'scoped_execution.rs'),
                         ('scoped_accelerated', leaf / 'scoped_accelerated.rs')):
        (tests / (target + '.rs')).write_text(test_source(path.read_text(), package))
    scoped = tests / 'scoped_accelerated'
    scoped.mkdir(exist_ok=True)
    require({p.name for p in (leaf / 'scoped_accelerated').rglob('*.rs')} == SCOPED_FILES, 'scoped test inventory')
    for name in SCOPED_FILES:
        text = references.adapt(name, (leaf / 'scoped_accelerated' / name).read_text())
        (scoped / name).write_text(test_source(text, package))


def unavailable(mode, selected):
    require(mode in MODES, 'unknown route')
    _, _, static, hosted = selected
    if mode in SCOPED and static != 'ready':
        return 'threaded execution rejected' if mode == 'threads-static' else 'static authority unavailable'
    if mode in ('required', 'stream-required', 'threads-required') and hosted != 'ready':
        return 'threaded execution rejected' if mode == 'threads-required' else 'required authority unavailable'
    return None


def check_result(result, answers, mode):
    require(mode in MODES and len(answers) == 256 and result.returncode == 0 and
            result.stdout.splitlines() == answers, 'oracle output/population')
    require(result.stderr == f'PARALLELHASH_EXECUTION: cases=256; mode={mode}; scoped={256 if mode in SCOPED else 0}\n',
            'mode/scoped completion population')


def check_execution_error(result, message, line=1):
    require(result.returncode == 1 and not result.stdout and result.stderr.strip() ==
            'Error: Custom { kind: InvalidData, error: ' + json.dumps(f'line {line}: {message}') + ' }',
            'unexpected execution rejection: ' + result.stderr[-1000:])


def campaign(api, consumer, cargo, env, data, selected):
    lines, answers, _ = data
    requests = '\n'.join(lines) + '\n'
    checked_env = dict(env, BRYNJA_REQUIRE_SCOPED_PARALLEL='1') if selected[2] == 'ready' else env
    for profile in ((), ('--release',)):
        tests = TESTS | ({'scoped_accelerated': 12} if selected[2] == 'ready' else {})
        for test, count in tests.items():
            result = api.run(cargo + ['test', '--offline', *profile, '--test', test], consumer, checked_env)
            require(f'test result: ok. {count} passed; 0 failed; 0 ignored;' in result.stdout, 'test population: ' + test)
        api.run(cargo + ['build', '--offline', *profile, '--bin', 'facade-consumer'], consumer, checked_env)
        for mode in MODES:
            command = [str(batch.binary(env, profile)), mode]
            error = unavailable(mode, selected)
            result = api.run(command, consumer, checked_env, data=requests, success=error is None)
            if error:
                check_execution_error(result, error)
                continue
            check_result(result, answers, mode)
            for invalid, message in batch.INVALID:
                for prefix in ('', lines[0] + '\n'):
                    batch.check_failure(api.run(command, consumer, checked_env,
                        data=prefix + invalid + '\n', success=False), message)
            print(f'PASS: ParallelHash execution: cases=256; mode={mode}; '
                  f'profile={"release" if profile else "debug"}; scoped={mode in SCOPED}', flush=True)


ALGORITHM_MUTANTS = (
    ('backend.rs', 'b"ParallelHash"', 'b"WrongDomain"'),
    ('collector.rs', 'prefix.left(block)?;', 'prefix.right(block)?;'),
    ('collector.rs', 'suffix.right(root.merged_leaves())?;', 'suffix.right(0)?;'),
)
CLEANUP_MUTANTS = (
    ('mod.rs', 'let _ = brynja_core::clear_owned_region(self.0);', 'let _ = self.0;',
     'execution', 'secret_reader_and_public_failure_cleanup'),
    ('stream.rs', 'self.root.cancel();\n        let _ = clear_owned_region(self.workspace);',
     'self.root.cancel();', 'execution_stream', 'callback_unwind_and_selection_failure_clear_partial_input'),
)


def mutants(api, consumer, roots, cargo, env, data):
    lines, answers, _ = data
    request = '\n'.join(lines) + '\n'
    for filename, before, after in ALGORITHM_MUTANTS:
        path = roots['brynja-hash-parallel'] / 'src/execution' / filename
        original = path.read_text()
        require(original.count(before) == 1, 'algorithm anchor')
        try:
            path.write_text(original.replace(before, after))
            api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
            result = api.run([str(batch.binary(env, True)), 'portable'], consumer, env, data=request)
            require(result.stdout.splitlines() != answers, 'algorithm mutant survived')
        finally:
            path.write_text(original)
    for filename, before, after, test, name in CLEANUP_MUTANTS:
        path = roots['brynja-hash-parallel'] / 'src/execution' / filename
        original = path.read_text()
        require(original.count(before) == 1, 'cleanup anchor')
        command = cargo + ['test', '--offline', '--release', '--test', test, name]
        try:
            path.write_text(original.replace(before, after))
            api.run(command + ['--no-run'], consumer, env)
            require_runtime_rejection(api.run(command + ['--', '--exact'], consumer, env, success=False), name)
        finally:
            path.write_text(original)
    api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
    check_result(api.run([str(batch.binary(env, True)), 'portable'], consumer, env, data=request), answers, 'portable')
    for test in ('execution', 'execution_stream'):
        result = api.run(cargo + ['test', '--offline', '--release', '--test', test], consumer, env)
        require(f'test result: ok. {TESTS[test]} passed; 0 failed; 0 ignored;' in result.stdout, 'restored test population')
    print('PASS: ParallelHash execution: three framing/domain and two cleanup mutants rejected', flush=True)


def fallback_mutant(api, consumer, roots, cargo, env, data):
    path = roots['brynja-hash-parallel'] / 'src/execution/backend.rs'
    original = path.read_text()
    before = 'Mode::Prefer(Some(s)) | Mode::Require(Some(s)) => Some(s),'
    require(original.count(before) == 1, 'fallback anchor')
    request = '\n'.join(data[0]) + '\n'
    errors = {'static': 'execution route mismatch', 'stream-static': 'missing stream root route',
              'threads-static': 'threaded execution route mismatch'}
    try:
        path.write_text(original.replace(before,
            'Mode::Prefer(Some(s)) | Mode::Require(Some(s)) => { let _ = s; None },'))
        api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
        for mode, error in errors.items():
            check_execution_error(api.run([str(batch.binary(env, True)), mode], consumer, env,
                data=request, success=False), error)
    finally:
        path.write_text(original)
    api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
    for mode in errors:
        result = api.run([str(batch.binary(env, True)), mode], consumer,
                         dict(env, BRYNJA_REQUIRE_SCOPED_PARALLEL='1'), data=request)
        check_result(result, data[1], mode)
    print('PASS: ParallelHash: compiled scalar fallback rejected by root/stream/threaded route checks', flush=True)


def execute(api, root, roots, cargo, env, native=False):
    consumer = root / 'parallelhash-execution-consumer'
    env = dict(env, CARGO_TARGET_DIR=str(root / 'parallelhash-execution-target'))
    data = batch.corpus()
    for package in ('brynja-crypto', 'brynja'):
        install(api, consumer, roots, package)
        metadata = api.resolved_metadata(cargo, consumer, env, roots)
        api.graph(json.loads(metadata.stdout), FEATURES, hosted=True, threaded=True)
        probe = cargo + ['run', '--offline', '--bin', 'route-probe']
        selected = selection.probe_result(api.run(probe, consumer, env).stdout)
        campaign(api, consumer, cargo, env, data, selected)
        mutants(api, consumer, roots, cargo, env, data)
        if native:
            require(selected[0] in ('avx2', 'arm-keccak'), 'required native instruction bundle unavailable')
            flags = '+avx2' if selected[0] == 'avx2' else '+neon,+sha2,+sha3'
            accelerated = dict(env, RUSTFLAGS='-C target-feature=' + flags,
                               CARGO_TARGET_DIR=str(root / 'parallelhash-execution-native-target'))
            selected = selection.probe_result(api.run(probe, consumer, accelerated).stdout)
            require(selected[2] == 'ready', 'native static authority unavailable')
            campaign(api, consumer, cargo, accelerated, data, selected)
            fallback_mutant(api, consumer, roots, cargo, accelerated, data)
        print(f'PASS: {package}: scheduled/streaming/threaded ParallelHash execution; native_requested={native}', flush=True)
