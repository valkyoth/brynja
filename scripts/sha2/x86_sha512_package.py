"""Packaged dedicated-SHA512 consumer and compiled regressions (external SDE)."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile


def helper(name):
    path = Path(__file__).with_name(name + '.py')
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check(sde, environment):
    ordinary = helper('check-sha2-execution')
    hardened = helper('check-sha2-hardened-execution')
    with tempfile.TemporaryDirectory(prefix='brynja-x86-sha512-package-') as directory:
        root = Path(directory)
        for fixture, checker, marker in (
            ('sha2-execution', ordinary, 'SHA-2 ordinary execution acceptance: PASS'),
            ('sha2-hardened-execution', hardened, 'SHA-2 hardened execution acceptance: PASS'),
        ):
            destination = root / fixture
            destination.mkdir()
            env = dict(environment, CARGO_TARGET_DIR=str(destination / 'target'))
            consumer, crates = ordinary.package(destination, env, fixture)
            command = ['cargo', '+1.98.1', 'build', '--offline', '--release', '--target',
                       'x86_64-unknown-linux-gnu', '--manifest-path', str(consumer / 'Cargo.toml')]
            binary = destination / 'target/x86_64-unknown-linux-gnu/release' / (
                'brynja-sha2-execution-fixture' if fixture == 'sha2-execution'
                else 'brynja-sha2-hardened-execution-fixture')

            def execute(failure=False):
                ordinary.run(command, consumer, env)
                result = subprocess.run([str(sde), '-arl', '--', str(binary), 'static'],
                                        cwd=consumer, env=env, capture_output=True, text=True, timeout=600)
                if failure:
                    if result.returncode == 0 or 'acceptance failed' not in result.stderr:
                        raise RuntimeError('compiled mutant was not rejected by the running consumer: '
                                           + result.stdout + result.stderr)
                elif result.returncode or marker not in result.stdout or 'wide=Static(X86Sha512)' not in result.stdout:
                    raise RuntimeError('packaged dedicated route failed: ' + result.stdout + result.stderr)

            execute()
            checker.negatives(consumer, env)
            cpu = crates['brynja-crypto-cpu'] / 'src'
            if fixture == 'sha2-execution':
                path = cpu / 'x86_sha512.rs'
                cases = [
                    ('a.wrapping_add(aa)', 'a'),
                    ('word(12)? as i64', 'word(13)? as i64'),
                    ('word(1)? as i64, word(2)? as i64', 'word(2)? as i64, word(1)? as i64'),
                ]
            else:
                path = cpu / 'x86_sha512.rs'
                cases = [
                    ('words::expand(&mut scratch.schedule, block)?;', 'let _ = block;'),
                    ('[aa, bb, cc, dd, ee, ff, gg, hh]', '[bb, aa, cc, dd, ee, ff, gg, hh]'),
                ]
            original = path.read_text()
            for before, after in cases:
                if original.count(before) != 1:
                    raise RuntimeError('stale/ambiguous mutation: ' + before)
                try:
                    path.write_text(original.replace(before, after))
                    execute(failure=True)
                finally:
                    path.write_text(original)
            execute()
            print(f'DEDICATED_X86_SHA512_PACKAGE: {fixture}; actual SDE route; ownership negatives; '
                  f'{len(cases)} compiled mutants rejected; restored source PASS', flush=True)
            extra = ['--target', 'x86_64-unknown-linux-gnu']
            if fixture == 'sha2-execution':
                ordinary.sha2_execution_faults.exercise(
                    consumer, crates, env,
                    ['cargo', '+1.98.1', 'run', '--offline', '--release', *extra, '--', 'static'],
                    ordinary.run, hosted=False, wide=True)
            else:
                cleanup_faults(crates, env, ordinary.run)
                helper('x86_sha512_faults').exercise(crates, env, ordinary.run)
                helper('sha2_hardened_cleanup_mutants').kernel_faults(
                    consumer, crates, env, ordinary.run, extra, ['static'])
            execute()


def cleanup_faults(crates, env, run):
    """Exercise the dedicated kernel's live operation guard, not digest-only output."""
    cpu = crates['brynja-crypto-cpu']
    manifest = cpu / 'Cargo.toml'
    tests = cpu / 'src/hardened_execution/tests.rs'
    original_manifest, original_tests = manifest.read_text(), tests.read_text()
    all_kernels = '''[
        Kernel::X86Sha256,
        Kernel::X86Sha512,
        Kernel::ArmSha256,
        Kernel::ArmSha512,
    ]'''
    if original_tests.count(all_kernels) != 2:
        raise RuntimeError('dedicated cleanup probe kernel list changed')
    # Only this kernel executes in these probes. Keep the count assertion valid
    # by compiling without SHA-NI (which is not a prerequisite of SHA512).
    isolated = dict(env, RUSTFLAGS='-C target-feature=+sha512,+avx2,+avx')
    patch = '\n[patch.crates-io]\n' + '\n'.join(
        f'{name} = {{ path = "{root.as_posix()}" }}' for name, root in crates.items()) + '\n'
    cases = (
        ('scratch.rs', 'clear_owned_region(&mut self.schedule)', 'Ok::<(), ()>(())'),
        ('scratch.rs', 'clear_owned_region(&mut self.vectors)', 'Ok::<(), ()>(())'),
        ('mod.rs', 'self.scratch.wipe();', 'let _ = &self.scratch;'),
        ('mod.rs', 'if !self.completed {', 'if false {'),
        ('mod.rs', 'self.check(wide)?;', 'let _ = wide;'),
    )
    try:
        manifest.write_text(original_manifest + patch)
        tests.write_text(original_tests.replace(all_kernels, '[Kernel::X86Sha512]'))
        for profile in ([], ['--release']):
            command = ['cargo', '+1.98.1', 'test', '--offline', '--features',
                       'hardened-execution,runtime-execution', '--lib', '--target',
                       'x86_64-unknown-linux-gnu', *profile, 'hardened_execution::tests',
                       '--', '--nocapture']
            result = run(command, cpu, isolated)
            if ('HARDENED_KERNEL_EXECUTION: X86Sha512; blocks=512' not in result.stdout
                    or '2 passed' not in result.stdout):
                raise RuntimeError('dedicated cleanup positive control did not execute')
            for name, before, after in cases:
                path = cpu / 'src/hardened_execution' / name
                original = path.read_text()
                if original.count(before) != 1:
                    raise RuntimeError('stale cleanup/route mutation: ' + before)
                try:
                    path.write_text(original.replace(before, after))
                    result = run(command, cpu, isolated, success=False)
                    if 'test result: FAILED' not in result.stdout:
                        raise RuntimeError('cleanup/route mutant failed before runtime')
                finally:
                    path.write_text(original)
            run(command, cpu, isolated)
    finally:
        manifest.write_text(original_manifest)
        tests.write_text(original_tests)
    print('DEDICATED_X86_SHA512_CLEANUP: ten compiled cleanup/quarantine/identity mutants rejected', flush=True)
