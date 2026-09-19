#!/usr/bin/env python3
"""Development scoped SHA-2 ownership regressions, not a new release gate."""
from pathlib import Path
import argparse
import shutil
import sys
import tempfile

from check import run
from check_callers import clean_environment

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'crates/brynja-hash-sha2'


def packaged(root):
    sys.path.insert(0, str(ROOT/'scripts/sha2'))
    import sha2_public_api as acceptance
    roots = acceptance.package_roots(root/'packages')
    fixture = root/'consumer'
    shutil.copytree(ROOT/'assurance/register-cleanup/in-place-sha2', fixture,
                    ignore=shutil.ignore_patterns('target', 'Cargo.lock'))
    manifest = fixture/'Cargo.toml'
    contents = manifest.read_text()
    for name in ('brynja-hash-sha2', 'brynja-crypto-cpu-std'):
        contents = contents.replace('path = "../../../crates/'+name+'"', 'path = "'+str(roots[name])+'"')
    manifest.write_text(contents)
    config = fixture/'.cargo'
    config.mkdir()
    (config/'config.toml').write_text('[patch.crates-io]\n'+''.join(
        f'{name} = {{ path = "{path.as_posix()}" }}\n' for name, path in roots.items()))
    acceptance.run(['cargo', '+1.98.1', 'generate-lockfile', '--offline'], cwd=fixture)
    acceptance.run(['cargo', '+1.98.1', 'test', '--locked', '--offline'], cwd=fixture)
    acceptance.run(['cargo', '+1.98.1', 'test', '--locked', '--offline', '--all-features'], cwd=fixture)
    print('Packaged scoped SHA-2: six named identities, SHA-256 known answer and 510 general parameters PASS', flush=True)


def main(native_x86=False):
    with tempfile.TemporaryDirectory(prefix='brynja-in-place-sha2-') as temporary:
        root = Path(temporary)
        crate = root/'sha2'
        shutil.copytree(SOURCE/'src', crate/'src')
        manifest = (SOURCE/'Cargo.toml').read_text()
        for name, value in (('edition', '"2024"'), ('rust-version', '"1.90"'),
                            ('license', '"MIT OR Apache-2.0"'),
                            ('homepage', '"https://github.com/valkyoth/brynja"'),
                            ('repository', '"https://github.com/valkyoth/brynja"')):
            manifest = manifest.replace(name+'.workspace = true', name+' = '+value)
        manifest = manifest.replace('[lints]\nworkspace = true', '[workspace]')
        for name in ('brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu'):
            manifest = manifest.replace(name+' = { workspace = true', name+' = { path = "'+str(ROOT/'crates'/name)+'"')
        (crate/'Cargo.toml').write_text(manifest)
        shutil.copyfile(SOURCE/'README.md', crate/'README.md')
        env = clean_environment()
        env['CARGO_TARGET_DIR'] = str(root/'target')
        run(['cargo', '+1.98.1', 'generate-lockfile', '--offline', '--manifest-path', str(crate/'Cargo.toml')], env)
        if native_x86:
            native_execution_mutants(crate, env)
            return
        path = crate/'src/hardened/in_place.rs'
        original = path.read_text()
        mutations = (
            ('scope guard disabled', 'let cleanup = Cleanup { owner: &mut self.owner, keep: false }', 'let cleanup = Cleanup { owner: &mut self.owner, keep: true }'),
            ('handle destructor disabled', 'fn drop(&mut self) { self.owner.wipe(); }', 'fn drop(&mut self) {}'),
            ('update cleanup disabled', 'let mut cleanup = Cleanup { owner: &mut *self.owner, keep: false }', 'let mut cleanup = Cleanup { owner: &mut *self.owner, keep: true }'),
            ('error revived', 'self.active = false;\n                let mut cleanup', 'self.active = true;\n                let mut cleanup'),
            ('identity not reinitialized', '$initialize(&mut self.owner, $initial);', ''),
            ('finalization omitted', 'self.owner.$finalize(partial, bits, $width);', ''),
            ('overflow accepted', 'self.owner.$message().checked_mul(8).ok_or(HardenedSha2Error::MessageTooLong)?', 'self.owner.$message().wrapping_mul(8)'),
            ('terminal secret output unguarded', 'let mut initialization = SecretRegionInitialization::begin(destination)?;', 'self.check()?; let mut initialization = SecretRegionInitialization::begin(destination)?;'),
        )
        for release in (False, True):
            command = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '--manifest-path', str(crate/'Cargo.toml'), '--lib', 'hardened::in_place']
            if release:
                command.append('--release')
            path.write_text(original)
            run(command, env)
            for label, before, after in mutations:
                if original.count(before) != 1:
                    raise ValueError('mutation source absent/ambiguous: '+label)
                path.write_text(original.replace(before, after))
                result = run(command, env, success=False)
                log = result.stdout + result.stderr
                if result.returncode == 0 or 'test result: FAILED' not in log:
                    raise ValueError('mutant must compile and fail at runtime: '+label+'\n'+log[-3000:])
            print(f'Scoped SHA-2: positive control and eight compiled mutants; release={release}: PASS', flush=True)
        path.write_text(original)
        general_mutants(crate, env)
        portable_transfer_mutants(crate, env)
        execution_mutants(crate, env)
        general_execution_mutants(crate, env)
        packaged(root)


def portable_transfer_mutants(crate, env):
    for family in ('32', '64'):
        path = crate / f'src/hardened/state{family}.rs'
        original = path.read_text()
        calls = [
            'brynja_core::copy_secret_region(destination, source)',
            'brynja_core::copy_secret_region(destination, tail)',
            'brynja_core::copy_secret_region(output, state)',
            ('brynja_core::copy_secret_region(destination, block)' if family == '32'
             else 'brynja_core::copy_secret_region(&mut self.block_copy, block)'),
            'brynja_core::copy_secret_region(\n                        core::slice::from_mut(target),\n                        core::slice::from_ref(byte),\n                    )',
        ]
        if family == '64':
            calls += ['brynja_core::copy_secret_region(&mut self.block_copy, &self.partial_input)',
                      'brynja_core::copy_secret_region(&mut self.block_copy, &self.padding_block)']
        mutations = [(call, 'Ok::<(), brynja_core::SecretMemoryError>(())') for call in calls]
        mutations += [('apply_secret_byte_mask(target, 0xff, 0x80 >> valid_bits)',
                       'apply_secret_byte_mask(target, 0xff, 0x40 >> valid_bits)')]
        # Independently omit each call site, including buffered and padding copies.
        expanded = []
        for before, after in mutations:
            start = 0
            count = 0
            while (index := original.find(before, start)) >= 0:
                expanded.append(original[:index] + after + original[index + len(before):])
                start = index + len(before)
                count += 1
            if not count:
                raise ValueError('missing portable SHA-2 mutation: ' + before)
        for release in (False, True):
            command = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '--manifest-path',
                       str(crate/'Cargo.toml'), '--features', 'general-sha512-t',
                       '--lib', 'hardened::in_place']
            if release:
                command.append('--release')
            path.write_text(original)
            run(command, env)
            for index, mutant in enumerate(expanded):
                path.write_text(mutant)
                result = run(command, env, success=False)
                log = result.stdout + result.stderr
                if not result.returncode or 'test result: FAILED' not in log:
                    raise ValueError(f'portable SHA-2/{family} mutant {index} must compile and fail: {log[-2000:]}')
            print(f'Borrowed SHA-2/{family} transfers: {len(expanded)} compiled mutants; release={release}: PASS', flush=True)
        path.write_text(original)


def general_mutants(crate, env):
    path = crate/'src/hardened/in_place/general.rs'
    original = path.read_text()
    mutations = (
        ('scope guard disabled', 'owner: &mut self.owner,\n            keep: false,', 'owner: &mut self.owner,\n            keep: true,'),
        ('handle destructor disabled', 'fn drop(&mut self) {\n        self.owner.wipe();\n    }', 'fn drop(&mut self) {}'),
        ('update cleanup disabled', 'owner: &mut *self.owner,\n            keep: false,', 'owner: &mut *self.owner,\n            keep: true,'),
        ('failed state revived', 'self.active = false;\n        let mut cleanup', 'self.active = true;\n        let mut cleanup'),
        ('parameter IV omitted', 'initialize64(&mut self.owner, self.parameter.initial_words());', ''),
        ('secret mask omitted', 'apply_secret_byte_mask(last, self.parameter.last_byte_mask(), 0);', 'apply_secret_byte_mask(last, 0xff, 0);'),
        ('secret identity substituted', 'Sha512TSecretDigest::from_region(\n            self.parameter,', 'Sha512TSecretDigest::from_region(\n            Sha512TBits::new(9)?, '),
        ('secret guard bypassed', 'let mut guard = SecretRegionInitialization::begin(destination)?;', 'self.check()?; let mut guard = SecretRegionInitialization::begin(destination)?;'),
    )
    for release in (False, True):
        command = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '--manifest-path', str(crate/'Cargo.toml'), '--features', 'general-sha512-t', '--lib', 'hardened::in_place::general']
        if release:
            command.append('--release')
        path.write_text(original)
        run(command, env)
        for label, before, after in mutations:
            if original.count(before) != 1:
                raise ValueError('general mutation source absent/ambiguous: '+label)
            path.write_text(original.replace(before, after))
            result = run(command, env, success=False)
            log = result.stdout + result.stderr
            if result.returncode == 0 or 'test result: FAILED' not in log:
                raise ValueError('general mutant must compile and fail at runtime: '+label+'\n'+log[-3000:])
        print(f'Scoped general SHA-512/t: positive control and eight compiled mutants; release={release}: PASS', flush=True)
    path.write_text(original)


def execution_mutants(crate, env):
    path = crate/'src/hardened_execution/in_place.rs'
    original = path.read_text()
    mutations = (
        ('scope cleanup', 'let cleanup = Cleanup { engine: &mut self.engine, keep: false }', 'let cleanup = Cleanup { engine: &mut self.engine, keep: true }'),
        ('handle cleanup', 'fn drop(&mut self) { self.engine.invalidate(); }', 'fn drop(&mut self) {}'),
        ('failed update cleanup', 'let mut cleanup = Cleanup { engine: &mut *self.engine, keep: false }', 'let mut cleanup = Cleanup { engine: &mut *self.engine, keep: true }'),
        ('IV initialization', '$initialize(&mut self.engine, $initial);', ''),
        ('secret finalization', 'self.engine.finish(input, $size, 0xff)?;\n                output.write', 'output.write'),
        ('secret output guard', 'self.secret(None, begin(destination, $size)?)', 'self.engine.check_bytes(0)?; self.secret(None, begin(destination, $size)?)'),
        ('public output transfer', 'brynja_core::copy_secret_region(destination, self.engine.owner.staged($size).ok_or(Error::OutputLength)?)?;', ''),
    )
    for release in (False, True):
        command = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '--manifest-path', str(crate/'Cargo.toml'), '--features', 'hardened-execution', '--lib', 'hardened_execution::in_place']
        if release:
            command.append('--release')
        path.write_text(original)
        run(command, env)
        for label, before, after in mutations:
            if original.count(before) != 1:
                raise ValueError('execution mutation absent/ambiguous: '+label)
            path.write_text(original.replace(before, after))
            result = run(command, env, success=False)
            if result.returncode == 0 or 'test result: FAILED' not in result.stdout + result.stderr:
                raise ValueError('execution mutant must compile and fail at runtime: '+label)
        print(f'Scoped execution: positive control and {len(mutations)} compiled cleanup/output/IV mutants; release={release}: PASS', flush=True)
    path.write_text(original)


def general_execution_mutants(crate, env):
    path = crate/'src/hardened_execution/in_place/general.rs'
    original = path.read_text()
    mutations = (
        ('scope cleanup', 'engine: &mut self.engine,\n            keep: false,', 'engine: &mut self.engine,\n            keep: true,'),
        ('handle cleanup', 'fn drop(&mut self) {\n        self.engine.invalidate();\n    }', 'fn drop(&mut self) {}'),
        ('failed update cleanup', 'engine: &mut *self.engine,\n            keep: false,', 'engine: &mut *self.engine,\n            keep: true,'),
        ('parameter IV', 'initialize64(&mut self.engine, self.parameter.initial_words());', ''),
        ('partial output mask', 'self.parameter.last_byte_mask(),', '0xff,'),
        ('secret identity', 'Sha512TSecretDigest::from_region(self.parameter, guard.finish()?)', 'Sha512TSecretDigest::from_region(Sha512TBits::new(9).map_err(|_| Error::Failed)?, guard.finish()?)'),
        ('terminal secret destination', 'let guard = begin(destination, self.parameter.output_bytes())?;\n        self.secret(None, guard)', 'self.engine.check_bytes(0)?; let guard = begin(destination, self.parameter.output_bytes())?;\n        self.secret(None, guard)'),
        ('IV work report', 'execution, true, true)?', 'execution, true, false)?'),
    )
    for release in (False, True):
        command = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '--manifest-path', str(crate/'Cargo.toml'), '--features', 'hardened-execution,general-sha512-t', '--lib', 'hardened_execution::in_place::general']
        if release:
            command.append('--release')
        path.write_text(original)
        run(command, env)
        for label, before, after in mutations:
            if original.count(before) != 1:
                raise ValueError('general execution mutation absent/ambiguous: '+label)
            path.write_text(original.replace(before, after))
            result = run(command, env, success=False)
            log = result.stdout + result.stderr
            if result.returncode == 0 or 'test result: FAILED' not in log:
                raise ValueError('general execution mutant must compile and fail at runtime: '+label+'\n'+log[-3000:])
        print(f'Scoped general execution: positive control and eight compiled lifecycle/identity/output/report mutants; release={release}: PASS', flush=True)
    path.write_text(original)


def native_execution_mutants(crate, env):
    sys.path.insert(0, str(ROOT/'scripts/sha2'))
    import hardened_native_host as host
    host.x86_host()  # Check every advertised CPU before selecting SHA-NI.
    env = dict(env, RUSTFLAGS='-C target-feature=+sha,+sse2', BRYNJA_REQUIRE_SCOPED_SHA2='1')
    path = crate/'src/hardened_execution/engine.rs'
    original = path.read_text()
    mutations = (
        ('restart authority bypass', 'self.invalidate();\n        self.execution.check(self.wide)?;', 'self.invalidate();'),
        ('stale work counts', 'self.report.message_blocks = 0;', ''),
        ('failed state revived', 'self.owner.wipe();\n        self.failed = true;', 'self.owner.wipe();\n        self.failed = false;'),
    )
    for release in (False, True):
        command = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '--manifest-path', str(crate/'Cargo.toml'), '--features', 'hardened-execution', '--lib', 'hardened_execution::in_place']
        if release:
            command.append('--release')
        path.write_text(original)
        run(command, env)
        for label, before, after in mutations:
            if original.count(before) != 1:
                raise ValueError('native execution mutation absent/ambiguous: '+label)
            path.write_text(original.replace(before, after))
            result = run(command, env, success=False)
            if result.returncode == 0 or 'test result: FAILED' not in result.stdout + result.stderr:
                raise ValueError('native execution mutant must compile and fail at runtime: '+label)
        print(f'Scoped native SHA-NI: positive control and three authority/counter/failure mutants; release={release}: PASS', flush=True)
    path.write_text(original)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-x86', action='store_true', help='only native SHA-NI authority/counter/failure mutations; validates actual Linux CPU support')
    main(parser.parse_args().native_x86)
