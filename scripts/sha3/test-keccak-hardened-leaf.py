#!/usr/bin/env python3
"""Development checks for distinct hardened SHA-3/SHAKE/cSHAKE batch owners.
Not the release gate or native qualification. Mutants require a native or
explicitly emulated matching target and its complete instruction bundle.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FEATURE = 'hardened-batch-execution'
spec = importlib.util.spec_from_file_location('cpu_batch', Path(__file__).with_name('test-keccak-hardened-batch.py'))
cpu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cpu)
run, require = cpu.run, cpu.require


def mutations(root, env, toolchain, target):
    command = ['cargo', '+'+toolchain, 'test', '--locked', '--offline',
               '-p', 'brynja-hash-sha3', '--no-default-features', '--features', FEATURE,
               '--target', target, '--lib', 'hardened_batch::']
    run(command, root, env)
    run(command[:-2] + ['--doc', 'hardened_batch'], root, env)
    source = root / 'crates/brynja-hash-sha3/src/hardened_batch'
    cases = [('workspace.rs', f'clear_owned_region(self.{field}.as_flattened_mut())', 'Ok::<(), ()>(())')
             for field in ('states', 'vector', 'starts', 'written')]
    cases += [('workspace.rs', f'clear_owned_region(&mut self.{field})', 'Ok::<(), ()>(())')
              for field in ('ready', 'eligible', 'absorbing')]
    cases += [('framing.rs', f'clear_owned_region(self.{field}.as_flattened_mut())', 'Ok::<(), ()>(())')
              for field in ('lengths', 'integers', 'cursor')]
    cases += [
        ('framing.rs', 'clear_owned_region(&mut self.suffix)', 'Ok::<(), ()>(())'),
        ('workspace.rs', 'self.scalar.wipe();', '// omitted nested scalar cleanup'),
        ('workspace.rs', 'self.wipe();\n        #[cfg(test)]', '// omitted Drop wipe\n        #[cfg(test)]'),
        ('output.rs', 'clear_owned_region(destination)', 'Ok::<(), ()>(())'),
        ('output.rs', 'destination.copy_from_slice(source);', '// omitted declassification'),
        ('mod.rs', 'destination.copy_from_slice(source);', '// omitted output commit'),
        ('mod.rs', 'self.workspace.wipe();', '// omitted operation wipe'),
        ('mod.rs', 'brynja_core::clear_owned_region(self.staging)', 'Ok::<(), ()>(())'),
        ('mod.rs', 'if !self.complete {', 'if false {'),
        ('engine.rs', 'executor.check()?;\n    Ok(report)', 'Ok(report)'),
        ('engine.rs', 'out.last_mut().ok_or(Error::Invariant)? &= mask', 'out.last_mut().ok_or(Error::Invariant)? |= mask'),
        ('framing.rs', '(4, 3)', '(6, 3)'),
        ('framing.rs', '(6, 3)', '(31, 5)'),
        ('framing.rs', '(31, 5)', '(6, 3)'),
        ('framing.rs', 'self.encode(0, 0, rate)?;', 'self.encode(0, 0, 0)?;'),
        ('framing.rs', 'self.set_len(8, padding)?;', 'self.set_len(8, 0)?;'),
    ]
    for name, before, after in cases:
        path = source / name
        original = path.read_text()
        require(original.count(before) == 1, 'leaf mutation anchor: ' + before)
        try:
            path.write_text(original.replace(before, after))
            result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=300)
            require(result.returncode != 0 and 'test result: FAILED' in result.stdout,
                    'mutant survived or failed to compile: ' + before + '\n' + result.stderr[-1500:])
        finally:
            path.write_text(original)
    run(command, root, env)
    print(f'Hardened Keccak leaf compiled cleanup/framing/quarantine mutants: {len(cases)} rejected')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', default='1.98.1')
    parser.add_argument('--target', default='x86_64-unknown-linux-gnu')
    args = parser.parse_args()
    require(args.target.startswith(('x86_64', 'aarch64')), 'unsupported architecture')
    with tempfile.TemporaryDirectory(prefix='brynja-keccak-hardened-leaf-') as directory:
        root = Path(directory)
        for crate in ('brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu', 'brynja-hash-sha3'):
            shutil.copytree(ROOT / 'crates' / crate, root / 'crates' / crate, ignore=shutil.ignore_patterns('target'))
        manifest = (ROOT / 'Cargo.toml').read_text().replace('default-members = ["crates/brynja"]',
                                                          'default-members = ["crates/brynja-hash-sha3"]')
        (root / 'Cargo.toml').write_text(manifest)
        env = dict(os.environ, CARGO_TARGET_DIR=str(root / 'target'))
        for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
            env.pop(key, None)
        env['RUSTFLAGS'] = '-C target-feature=' + ('+avx,+avx2' if args.target.startswith('x86_64') else '+neon')
        if args.target == 'aarch64-unknown-linux-musl':
            env['RUSTFLAGS'] += ' -C linker=rust-lld'
        env['RUSTDOCFLAGS'] = env['RUSTFLAGS']
        env['BRYNJA_REQUIRE_HARDENED_KECCAK_LEAF'] = '1'
        run(['cargo', '+'+args.toolchain, 'generate-lockfile', '--offline'], root, env)
        mutations(root, env, args.toolchain, args.target)


if __name__ == '__main__':
    main()
