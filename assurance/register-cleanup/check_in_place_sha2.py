#!/usr/bin/env python3
"""Development scoped SHA-2 ownership regressions, not a new release gate."""
from pathlib import Path
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
    manifest.write_text(manifest.read_text().replace(
        'path = "../../../crates/brynja-hash-sha2"',
        'path = "'+str(roots['brynja-hash-sha2'])+'"'))
    config = fixture/'.cargo'
    config.mkdir()
    (config/'config.toml').write_text('[patch.crates-io]\n'+''.join(
        f'{name} = {{ path = "{path.as_posix()}" }}\n' for name, path in roots.items()))
    acceptance.run(['cargo', '+1.98.1', 'generate-lockfile', '--offline'], cwd=fixture)
    acceptance.run(['cargo', '+1.98.1', 'test', '--locked', '--offline'], cwd=fixture)
    acceptance.run(['cargo', '+1.98.1', 'test', '--locked', '--offline', '--all-features'], cwd=fixture)
    print('Packaged scoped SHA-2: six named identities, SHA-256 known answer and 510 general parameters PASS', flush=True)


def main():
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
        packaged(root)


def general_mutants(crate, env):
    path = crate/'src/hardened/in_place/general.rs'
    original = path.read_text()
    mutations = (
        ('scope guard disabled', 'owner: &mut self.owner,\n            keep: false,', 'owner: &mut self.owner,\n            keep: true,'),
        ('handle destructor disabled', 'fn drop(&mut self) {\n        self.owner.wipe();\n    }', 'fn drop(&mut self) {}'),
        ('update cleanup disabled', 'owner: &mut *self.owner,\n            keep: false,', 'owner: &mut *self.owner,\n            keep: true,'),
        ('failed state revived', 'self.active = false;\n        let mut cleanup', 'self.active = true;\n        let mut cleanup'),
        ('parameter IV omitted', 'initialize64(&mut self.owner, self.parameter.initial_words());', ''),
        ('secret mask omitted', '&= self.parameter.last_byte_mask();', '&= 0xff;'),
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


if __name__ == '__main__':
    main()
