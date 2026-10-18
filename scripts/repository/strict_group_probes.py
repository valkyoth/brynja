"""Ownership and runtime mutations of extracted group consumers only."""
import json

from strict_public_consumer import diagnostic, shared
from strict_accelerated_mutants import rejection


def negatives(api, consumer, cargo, env):
    path = consumer / 'src/lib.rs'
    original = path.read_text()
    count = 0
    try:
        for family, owners in (('batch', ('Session', "Output<'static>")),
                               ('parallelhash', ('Session', 'CompiledSession', "Output<'static>"))):
            for owner in owners:
                name = f'brynja_strict::{family}::{owner}'
                path.write_text(f'pub fn present(_:Option<{name}>){{}}')
                api.run(cargo + ['check', '--locked', '--offline', '--lib'], consumer, env)
                for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                    path.write_text(f'fn bound<T:{bound}>(){{}} fn probe(){{bound::<{name}>();}}')
                    result = api.run(cargo + ['check', '--locked', '--offline', '--lib', '--message-format=json'], consumer, env, success=False)
                    shared.require(diagnostic(result, 'E0277'), 'strict group ownership diagnostic')
                    count += 1
        for family, owner, args, call, expose in (
            ('batch', 'Session', ", i:&[Option<m::Input<'_>>;8]", 'digest(i,10000,&m::Cancellation::new())', 'expose(0)'),
            ('parallelhash', 'Session', '', 'hash(b"abc",1,b"")', 'expose()'),
            ('parallelhash', 'CompiledSession', '', 'hash(b"abc",1,b"")', 'expose()'),
        ):
            head = f'use brynja_strict::{family} as m;\n'
            positive = head + f"fn loan<'a>(s:&'a mut m::{owner}{args})->Result<m::Output<'a>,m::Error>{{s.{call}}}"
            path.write_text(positive)
            api.run(cargo + ['check', '--locked', '--offline', '--lib'], consumer, env)
            for source, code in (
                (positive.replace("Output<'a>", "Output<'static>"), None),
                (head + f'fn reuse(s:&mut m::{owner}{args})->Result<(),m::Error>{{let first=s.{call}?; let _second=s.{call}?; let _=first.{expose}; Ok(())}}', 'E0499'),
                (head + "fn copy(o:m::Output<'_>){let _=o.declassify(" +
                 ('[const {None};8]' if family == 'batch' else '&mut []') + ');}', 'E0061'),
            ):
                path.write_text(source)
                result = api.run(cargo + ['check', '--locked', '--offline', '--lib', '--message-format=json'], consumer, env, success=False)
                valid = diagnostic(result, code) if code else result.returncode == 101 and 'lifetime may not live long enough' in result.stdout
                shared.require(valid, 'strict group lifetime/classification diagnostic')
                count += 1
    finally:
        path.write_text(original)
    shared.require(count == 34, 'strict group negative population')
    print('PASS: strict groups; 34 ownership/lifetime/classification negatives', flush=True)


def mutations(native):
    cpu, parallel = 'brynja-crypto-cpu-std', 'brynja-hash-parallel-std'
    result = [
        (cpu, 'strict_batch/mod.rs', 'if self.quarantined {', 'if false {', 'batch_lifecycle'),
        (cpu, 'strict_batch/mod.rs', 'if types::reusable(&result) {', 'if false {', 'batch_lifecycle'),
        (cpu, 'strict_batch/mod.rs', 'out.copy_from_slice(source);', 'out.fill(0);', 'batch_lifecycle'),
        (cpu, 'strict_batch/worker.rs', 'brynja_core::copy_secret_region(slot, source)',
         'brynja_core::copy_secret_region(&mut [], &[])', 'batch_oracles'),
        (cpu, 'strict_batch/worker.rs', 'Ok(sha256::Input::new(\n        algorithm,',
         'Ok(sha256::Input::new(\n        sha256::Algorithm::Sha256,', 'batch_oracles'),
        (parallel, 'strict_execution/mod.rs', 'if block_bytes == 0', 'if false', 'parallel_lifecycle'),
        (parallel, 'strict_execution/mod.rs', 'destination.copy_from_slice(self.expose());',
         'destination.fill(0);', 'parallel_lifecycle'),
        (parallel, 'strict_execution/mod.rs', 'if cancel.is_cancelled() {', 'if false {', 'parallel_lifecycle'),
        (parallel, 'strict_execution/worker.rs', 'brynja_core::copy_secret_region(destination, source)',
         'brynja_core::copy_secret_region(&mut [], &[])', 'parallel_oracles'),
    ]
    if native:
        result += [
            (cpu, 'strict_batch/worker.rs', 'Ok(Report::$kind(report))',
             'let mut report = report; report.vector_calls = 0; Ok(Report::$kind(report))', 'batch_oracles'),
            (cpu, 'strict_batch/worker.rs', '''Some(owner) => $api::Executor::with_session(owner.session().map_err(|e| Error::$kind($api::Error::Backend(e)))?,
                    $api::Mode::Require, 1).map_err(Error::$kind)?,''',
             'Some(_owner) => $api::Executor::portable(),', 'batch_oracles'),
            (parallel, 'strict_execution/compiled.rs', 'if self.quarantined {', 'if false {', 'parallel_lifecycle'),
            (parallel, 'strict_execution/compiled.rs', 'self.quarantined = false;', 'self.quarantined = true;', 'parallel_lifecycle'),
            (parallel, 'strict_execution/compiled/worker.rs', 'brynja_core::copy_secret_region(destination, source)',
             'brynja_core::copy_secret_region(&mut [], &[])', 'parallel_oracles'),
        ]
    return result


def mutants(api, consumer, roots, cargo, env, native):
    for package, name, before, after, test in mutations(native):
        path = roots[package] / 'src' / name
        original = path.read_text()
        shared.require(before in original, 'strict group mutation anchor: ' + name)
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ['--release']):
                command = cargo + ['test', '--locked', '--offline', *profile, '--test', 'acceptance']
                if native:
                    command += ['--features', 'native']
                api.run(command + ['--no-run'], consumer, env)
                result = api.run(command + [test, '--', '--exact', '--nocapture'], consumer, env, success=False)
                rejection(result, test, 6)
        finally:
            path.write_text(original)
    print(f'PASS: strict groups; native={native}; {len(mutations(native))*2} public behavioral mutations rejected', flush=True)


def parallel_instrumented(api, roots, cargo, env):
    """Companion private test proves SIMD work; public API exposes no counter."""
    crate = roots['brynja-hash-parallel-std']
    manifest = crate / 'Cargo.toml'
    original = manifest.read_text()
    path = crate / 'src/strict_execution/compiled/worker.rs'
    pristine = path.read_text()
    before = '''let executor = batch::Executor::with_session(
                owner.session().map_err(|_| Error::Invariant)?,
                batch::Mode::Prefer,
                1,
            )
            .map_err(|_| Error::Invariant)?;'''
    test = 'strict_execution::compiled::tests::native::actual_parallel_single_and_simd_waves_match_all_identities'
    shared.require(pristine.count(before) == 1, 'strict parallel portable substitution anchor')
    try:
        patches = ''.join(f'{name}={{path={json.dumps(str(root))}}}\n' for name, root in roots.items())
        manifest.write_text(original + '\n[workspace]\n[patch.crates-io]\n' + patches)
        api.run(cargo + ['generate-lockfile', '--offline'], crate, env)
        for profile in ([], ['--release']):
            command = cargo + ['test', '--locked', '--offline', *profile, '--no-default-features',
                               '--features', 'strict-acceleration', '--lib']
            result = api.run(command + [test, '--', '--exact', '--nocapture'], crate, env)
            instrumented_check(result)
            try:
                path.write_text(pristine.replace(before, 'let executor = batch::Executor::portable();'))
                api.run(command + ['--no-run'], crate, env)
                result = api.run(command + [test, '--', '--exact', '--nocapture'], crate, env, success=False)
                shared.require(result.returncode == 101 and f'test {test} ... FAILED' in result.stdout
                               and 'test result: FAILED. 0 passed; 1 failed; 0 ignored;' in result.stdout
                               and 'VECTOR_CALLS.load' in result.stderr, 'strict parallel scalar-only mutant survived/unrelated failure')
            finally:
                path.write_text(pristine)
            instrumented_check(api.run(command + [test, '--', '--exact', '--nocapture'], crate, env))
    finally:
        path.write_text(pristine)
        manifest.write_text(original)
    print('PASS: strict parallel companion: debug/release vector observations; two portable-substitution mutants rejected', flush=True)


def instrumented_check(result):
    import re
    summaries = re.findall(r'^test result: .*$', result.stdout, re.M)
    shared.require(result.returncode == 0 and len(summaries) == 1 and
                   summaries[0].startswith('test result: ok. 1 passed; 0 failed; 0 ignored;'), 'strict parallel companion population')
    markers = [s for s in result.stdout.splitlines() if s.startswith('STRICT_PARALLELHASH:')]
    shared.require(markers in (
        ['STRICT_PARALLELHASH: Single(X86Keccak); differential=288', 'STRICT_PARALLELHASH: Batch(Avx2); differential=288'],
        ['STRICT_PARALLELHASH: Single(ArmKeccak); differential=288', 'STRICT_PARALLELHASH: Batch(Neon); differential=288']),
        'strict parallel companion routes')
