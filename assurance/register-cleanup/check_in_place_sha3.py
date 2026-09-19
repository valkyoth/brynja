#!/usr/bin/env python3
"""Development scoped-owner regressions; no release workflow changes."""
from pathlib import Path
import argparse
import platform
import shutil
import sys
import tempfile

from check import run
from check_callers import clean_environment

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'crates/brynja-hash-sha3'


def packaged(root, env=None):
    sys.path.insert(0, str(ROOT/'scripts/sha3'))
    import sha3_public_api as acceptance
    roots = acceptance.package_roots(root/'packages')
    fixture = root/'consumer'
    shutil.copytree(ROOT/'assurance/register-cleanup/in-place-sha3', fixture,
                    ignore=shutil.ignore_patterns('target', 'Cargo.lock'))
    manifest = fixture/'Cargo.toml'
    contents = manifest.read_text()
    for name in ('brynja-hash-sha3', 'brynja-crypto-cpu', 'brynja-crypto-cpu-std'):
        contents = contents.replace('path = "../../../crates/'+name+'"', 'path = "'+str(roots[name])+'"')
    manifest.write_text(contents)
    config = fixture/'.cargo'
    config.mkdir()
    (config/'config.toml').write_text('[patch.crates-io]\n'+''.join(
        f'{name} = {{ path = "{path.as_posix()}" }}\n' for name, path in roots.items()))
    acceptance.run(['cargo', '+1.98.1', 'generate-lockfile', '--offline'], cwd=fixture)
    acceptance.run(['cargo', '+1.98.1', 'test', '--locked', '--offline'], cwd=fixture)
    acceptance.run(['cargo', '+1.98.1', 'test', '--locked', '--offline', '--all-features'], cwd=fixture)
    if env is not None:
        run(['cargo', '+1.98.1', '--config', str(config/'config.toml'), 'test', '--locked', '--offline', '--manifest-path', str(manifest), '--all-features', 'execution::tests'], env)
    print('Packaged scoped SHA-3 downstream known-answer/ownership smoke: PASS', flush=True)


def main(native_x86=False):
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
        if native_x86:
            if platform.system() != 'Linux' or platform.machine() != 'x86_64':
                raise ValueError('scoped native Keccak requires Linux x86_64')
            flags = [set(line.split(':', 1)[1].split()) for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('flags')]
            if not flags or not all('avx2' in features for features in flags):
                raise ValueError('every advertised CPU must support AVX2')
            env.update(RUSTFLAGS='-C target-feature=+avx2', BRYNJA_REQUIRE_SCOPED_KECCAK='1')
            execution_mutants(crate, env)
            scoped_xof_execution_mutants(crate, env)
            packaged(root, env)
            return
        path = crate/'src/hardened/in_place.rs'
        original = path.read_text()
        mutations = (
            ('scope guard disabled', 'let cleanup = Cleanup { owner: &mut self.owner, keep: false }', 'let cleanup = Cleanup { owner: &mut self.owner, keep: true }'),
            ('handle wipe removed', 'fn drop(&mut self) { self.owner.wipe(); }', 'fn drop(&mut self) {}'),
            ('update cleanup disabled', 'let mut cleanup = Cleanup { owner: &mut *self.owner, keep: false }', 'let mut cleanup = Cleanup { owner: &mut *self.owner, keep: true }'),
            ('failed update reusable', 'self.active = false;\n                let mut cleanup', 'self.active = true;\n                let mut cleanup'),
            ('stage omitted', 'self.owner.stage_fixed($width)?;', ''),
            ('public copy omitted', 'brynja_core::copy_secret_region(destination, staged)?;', ''),
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
            print(f'Scoped SHA-3: positive control and {len(mutations)} compiled mutants; release={release}: PASS', flush=True)
        path.write_text(original)
        xof_mutants(crate, env)
        portable_transfer_mutants(crate, env)
        packaged(root)


def portable_transfer_mutants(crate, env):
    sponge = crate/'src/hardened/sponge.rs'
    fixed = crate/'src/hardened/fixed.rs'
    originals = {path: path.read_text() for path in (sponge, fixed)}
    calls = (
        'brynja_core::copy_secret_region(\n                self.partial_input',
        'brynja_core::copy_secret_region(self.partial_input',
        'brynja_core::copy_secret_region(\n            self.squeeze_staging',
        'brynja_core::copy_secret_region(\n                target,',
        'brynja_core::copy_secret_region(\n                self.squeeze_staging',
    )
    mutations = [(sponge, call, call.replace('brynja_core::copy_secret_region', 'omitted_copy'), 1)
                 for call in calls]
    mutations += [(sponge, f'apply_secret_byte_mask({name}, low_mask(valid), 0)',
                   f'apply_secret_byte_mask({name}, 0xff, 0)', 1) for name in ('target', 'tail')]
    mutations.append((fixed, 'brynja_core::copy_secret_region(destination, output)?;', '', 2))
    for name in ('absorb_partial', 'absorb_slice', 'absorb_padding'):
        source = originals[sponge]
        start = source.index('    fn '+name+'(')
        end = source.index('\n    fn ', start + 1)
        body = source[start:end]
        if body.count('xor_byte(state, input);') != 1:
            raise ValueError('portable absorption mutation absent/ambiguous: '+name)
        mutations.append((sponge, body, body.replace('xor_byte(state, input);', ''), 1))
    mutations += [
        (sponge, 'let _ = brynja_core::copy_secret_region(destination, source);', '', 1),
        (sponge, 'copy_byte(target, byte);', '', 1),
        (sponge, 'apply_secret_byte_mask(target, low_mask(valid_bits), 0)',
         'apply_secret_byte_mask(target, 0xff, 0)', 1),
        (sponge, 'apply_secret_byte_mask(target, 0xff, 1_u8 << bit_in_byte)',
         'apply_secret_byte_mask(target, 0xff, 0)', 1),
        (sponge, 'apply_secret_byte_mask(last, 0xff, 0x80)',
         'apply_secret_byte_mask(last, 0xff, 0)', 1),
        (sponge, 'xor_secret_byte_bits(destination, source, 0, 8, 0)',
         'xor_secret_byte_bits(destination, source, 0, 1, 0)', 1),
        (sponge, '.map(|byte| (byte, input.valid_bits_in_last_byte()))',
         '.map(|byte| (byte, 1))', 1),
    ]
    for release in (False, True):
        command = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '--manifest-path',
                   str(crate/'Cargo.toml'), '--lib', 'hardened::sponge::tests']
        if release:
            command.append('--release')
        for path, source in originals.items():
            path.write_text(source)
        run(command, env)
        for path, before, after, count in mutations:
            for target, source in originals.items():
                target.write_text(source)
            source = originals[path]
            if source.count(before) != count:
                raise ValueError('portable transfer mutation absent/ambiguous: '+before)
            changed = source.replace(before, after)
            if 'omitted_copy' in after:
                changed += '\nfn omitted_copy(_: &mut [u8], _: &[u8]) -> Result<(), brynja_core::SecretMemoryError> { Ok(()) }\n'
            path.write_text(changed)
            result = run(command, env, success=False)
            if result.returncode == 0 or 'test result: FAILED' not in result.stdout + result.stderr:
                raise ValueError('portable transfer mutant must compile and fail at runtime: '+before)
        print(f'Portable sponge: {len(mutations)} compiled transfer/mask/framing mutants; release={release}: PASS', flush=True)
    for path, source in originals.items():
        path.write_text(source)


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


def execution_mutants(crate, env):
    path = crate/'src/hardened/accelerated/in_place.rs'
    engine = crate/'src/hardened/accelerated/engine.rs'
    reader = crate/'src/hardened/accelerated/reader.rs'
    xof = crate/'src/hardened/accelerated/xof.rs'
    originals = {target: target.read_text() for target in (path, engine, reader, xof)}
    mutations = (
        (path, 'scope cleanup', 'fn drop(&mut self) {\n        self.0.clear();\n    }', 'fn drop(&mut self) {}', 1),
        (path, 'handle cleanup', 'fn drop(&mut self) { self.storage.clear(); }', 'fn drop(&mut self) {}', 1),
        (path, 'staging cleanup', 'let _ = clear_owned_region(&mut self.stage.0);', '', 1),
        (path, 'failed update staging', 'if result.is_err() { self.storage.clear(); }', '', 1),
        (path, 'domain suffix', 'self.storage.engine.finish(input, 0x06, 3)?;', 'self.storage.engine.finish(input, 0x1f, 5)?;', 2),
        (path, 'public commit', 'brynja_core::copy_secret_region(output, buffer).map_err(|_| Error::SecretMemory)?;', '', 1),
        (path, 'secret guard', 'let length = output.len();', 'self.storage.engine.check(false)?; let length = output.len();', 1),
        (engine, 'restart authority', 'self.cancel();\n        self.session.check().map_err(Error::Backend)?;', 'self.cancel();', 1),
        (engine, 'restart phase', 'self.squeezing = false;', '', 1),
        (engine, 'absorbed high bit', 'xor_secret_byte_bits(target, byte, 0, 8, 0)', 'xor_secret_byte_bits(target, byte, 0, 7, 0)', 1),
        (engine, 'partial input bits', 'xor_secret_byte_bits(target, byte, 0, valid, 0)', 'xor_secret_byte_bits(target, byte, 0, 1, 0)', 1),
        (engine, 'last padding bit', 'xor_secret_byte_bits(last, &0x80, 7, 1, 7)', 'xor_secret_byte_bits(last, &0, 7, 1, 7)', 1),
        (engine, 'squeeze transfer', 'brynja_core::copy_secret_region(\n                output,', 'omitted_transfer(\n                output,', 1),
        (reader, 'public transfer', 'brynja_core::copy_secret_region(output, buffer).map_err(|_| Error::SecretMemory)?;', '', 1),
        (reader, 'reader masks', 'u8::MAX >> 8_u8.saturating_sub(valid)', 'u8::MAX', 2),
        (xof, 'in-place public mask', 'u8::MAX >> 8_u8.saturating_sub(valid)', 'u8::MAX', 1),
    )
    for release in (False, True):
        command = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '--manifest-path', str(crate/'Cargo.toml'), '--features', 'hardened-execution', '--lib', 'hardened::accelerated']
        if release:
            command.append('--release')
        for target, source in originals.items():
            target.write_text(source)
        run(command, env)
        for target, label, before, after, count in mutations:
            for original_path, source in originals.items():
                original_path.write_text(source)
            source = target.read_text()
            if source.count(before) != count:
                raise ValueError('scoped execution mutation absent/ambiguous: '+label)
            mutated = source.replace(before, after)
            if 'omitted_transfer(' in after:
                mutated += '\nfn omitted_transfer(_: &mut [u8], _: &[u8]) -> Result<(), brynja_core::SecretMemoryError> { Ok(()) }\n'
            target.write_text(mutated)
            result = run(command, env, success=False)
            if result.returncode == 0 or 'test result: FAILED' not in result.stdout + result.stderr:
                raise ValueError('scoped execution mutant must compile and fail at runtime: '+label)
        print(f'Scoped native Keccak: positive control and {len(mutations)} compiled cleanup/authority/framing mutants; release={release}: PASS', flush=True)
    for target, source in originals.items():
        target.write_text(source)


def scoped_xof_execution_mutants(crate, env):
    api = crate/'src/hardened/accelerated/in_place/xof.rs'
    core = api.parent/'xof/core.rs'
    originals = {path: path.read_text() for path in (api, core)}
    mutations = (
        (core, 'scope cleanup', 'self.0.clear();', '', 1),
        (core, 'borrowed cleanup', 'fn drop(&mut self) {\n        self.storage.clear();\n    }', 'fn drop(&mut self) {}', 1),
        (core, 'operation error cleanup', 'if !self.complete {', 'if false {', 1),
        (core, 'successful operation staging', 'else {\n            let _ = clear_owned_region(&mut self.storage.inner.stage.0);\n        }', 'else {}', 1),
        (core, 'terminal secret destination', 'let length = output.len();', 'self.storage.inner.engine.check(true)?; let length = output.len();', 1),
        (core, 'custom domain ignored', 'self.domain = if customized { [0x04, 3] } else { [0x1f, 5] };', 'self.domain = if customized { [0x1f, 5] } else { [0x1f, 5] };', 1),
        (core, 'secret final mask', 'u8::MAX >> 8_u8.saturating_sub(valid)', 'u8::MAX', 1),
        (core, 'invalid final bits accepted', 'return Err(Error::OutputLength);', '', 1),
        (api, 'public final mask', 'u8::MAX >> 8_u8.saturating_sub(valid)', 'u8::MAX', 1),
        (api, 'reader transfer destroys source', 'Ok($reader { inner: self.inner })', 'self.inner.storage.clear(); Ok($reader { inner: self.inner })', 1),
    )
    for release in (False, True):
        command = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '--manifest-path', str(crate/'Cargo.toml'), '--features', 'hardened-execution', '--lib', 'hardened::accelerated::in_place::xof']
        if release:
            command.append('--release')
        for path, source in originals.items():
            path.write_text(source)
        run(command, env)
        for path, label, before, after, count in mutations:
            for target, source in originals.items():
                target.write_text(source)
            if originals[path].count(before) != count:
                raise ValueError('scoped XOF execution mutation absent/ambiguous: '+label)
            path.write_text(originals[path].replace(before, after))
            result = run(command, env, success=False)
            if result.returncode == 0 or 'test result: FAILED' not in result.stdout + result.stderr:
                raise ValueError('scoped XOF execution mutant must compile and fail at runtime: '+label+'\n'+(result.stdout+result.stderr)[-2000:])
        print(f'Scoped native XOF: positive control and ten compiled cleanup/framing/output mutants; release={release}: PASS', flush=True)
    for path, source in originals.items():
        path.write_text(source)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-x86', action='store_true', help='native AVX2 scoped execution mutations and packaged consumer; checks Linux CPU support')
    main(parser.parse_args().native_x86)
