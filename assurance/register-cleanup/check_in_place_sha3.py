#!/usr/bin/env python3
"""Development scoped-owner regressions; no release workflow changes."""
from pathlib import Path
import shutil
import sys
import tempfile

from check import run
from check_callers import clean_environment

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'crates/brynja-hash-sha3'


def packaged(root):
    sys.path.insert(0, str(ROOT/'scripts/sha3'))
    import sha3_public_api as acceptance
    roots = acceptance.package_roots(root/'packages')
    fixture = root/'consumer'
    shutil.copytree(ROOT/'assurance/register-cleanup/in-place-sha3', fixture,
                    ignore=shutil.ignore_patterns('target', 'Cargo.lock'))
    manifest = fixture/'Cargo.toml'
    manifest.write_text(manifest.read_text().replace(
        'path = "../../../crates/brynja-hash-sha3"',
        'path = "'+str(roots['brynja-hash-sha3'])+'"'))
    config = fixture/'.cargo'
    config.mkdir()
    (config/'config.toml').write_text('[patch.crates-io]\n'+''.join(
        f'{name} = {{ path = "{path.as_posix()}" }}\n' for name, path in roots.items()))
    acceptance.run(['cargo', '+1.98.1', 'generate-lockfile', '--offline'], cwd=fixture)
    acceptance.run(['cargo', '+1.98.1', 'test', '--locked', '--offline'], cwd=fixture)
    print('Packaged scoped SHA-3 downstream known-answer/ownership smoke: PASS', flush=True)


def main():
    with tempfile.TemporaryDirectory(prefix='brynja-in-place-sha3-') as temporary:
        root = Path(temporary)
        crate = root / 'sha3'
        shutil.copytree(SOURCE / 'src', crate / 'src')
        manifest = (SOURCE / 'Cargo.toml').read_text()
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
            ('handle wipe removed', 'fn drop(&mut self) { self.owner.wipe(); }', 'fn drop(&mut self) {}'),
            ('update cleanup disabled', 'let mut cleanup = Cleanup { owner: &mut *self.owner, keep: false }', 'let mut cleanup = Cleanup { owner: &mut *self.owner, keep: true }'),
            ('failed update reusable', 'self.active = false;\n                let mut cleanup', 'self.active = true;\n                let mut cleanup'),
            ('stage omitted', 'self.owner.stage_fixed($width);', ''),
            ('fixed suffix corrupted', 'self.owner.finalize(partial, SHA3_SUFFIX, SHA3_SUFFIX_BITS);', 'self.owner.finalize(partial, 0x1f, SHA3_SUFFIX_BITS);'),
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
            print(f'Scoped SHA-3: positive control and six compiled mutants; release={release}: PASS', flush=True)
        path.write_text(original)
        xof_mutants(crate, env)
        packaged(root)


def xof_mutants(crate, env):
    path = crate/'src/hardened/in_place/xof.rs'
    original = path.read_text()
    mutations = (
        ('scope guard disabled', 'let cleanup = Cleanup { owner: &mut self.owner, keep: false }', 'let cleanup = Cleanup { owner: &mut self.owner, keep: true }'),
        ('borrowed destructor disabled', 'fn drop(&mut self) {\n        self.owner.wipe();\n    }', 'fn drop(&mut self) {}'),
        ('operation cleanup disabled', 'owner: &mut *self.owner,\n            keep: false,', 'owner: &mut *self.owner,\n            keep: true,'),
        ('error revived', 'self.active = false;\n        let mut cleanup', 'self.active = true;\n        let mut cleanup'),
        ('secret terminal output unguarded', 'let length = destination.len();', 'if !self.active { return Err(HardenedSha3Error::StateConsumed); }\n        let length = destination.len();'),
        ('reader transition wipes state', 'Ok($reader { inner: self.inner })', 'self.inner.owner.wipe(); Ok($reader { inner: self.inner })'),
        ('customization ignored', 'if owner.cshake_is_customized() {', 'if false {'),
        ('SHAKE suffix corrupted', 'owner.finalize(partial, SHAKE_SUFFIX, SHAKE_SUFFIX_BITS);', 'owner.finalize(partial, 0x06, SHAKE_SUFFIX_BITS);'),
    )
    for release in (False, True):
        command = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '--manifest-path', str(crate/'Cargo.toml'), '--lib', 'hardened::in_place::xof']
        if release:
            command.append('--release')
        path.write_text(original)
        run(command, env)
        for label, before, after in mutations:
            count = 2 if label == 'reader transition wipes state' else 1
            if original.count(before) != count:
                raise ValueError('XOF mutation source absent/ambiguous: '+label)
            path.write_text(original.replace(before, after))
            result = run(command, env, success=False)
            log = result.stdout + result.stderr
            if result.returncode == 0 or 'test result: FAILED' not in log:
                raise ValueError('XOF mutant must compile and fail at runtime: '+label+'\n'+log[-3000:])
        print(f'Scoped XOF: positive control and eight compiled mutants; release={release}: PASS', flush=True)
    path.write_text(original)


if __name__ == '__main__':
    main()
