#!/usr/bin/env python3
"""Real packaged consumers, ownership negatives, and compiled batch mutants."""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/sha2'))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(command, cwd, env, data=None):
    return subprocess.run(command, cwd=cwd, env=env, input=data, text=True, capture_output=True, timeout=300)


def main(native=False):
    helper = load('keccak_batch_package', ROOT / 'scripts/sha2/check-sha2-execution.py')
    differential = load('keccak_batch_differential', ROOT / 'scripts/sha3/check-keccak-batch.py')
    with tempfile.TemporaryDirectory(prefix='brynja-keccak-batch-package-') as directory:
        root = Path(directory)
        env = dict(os.environ, CARGO_TARGET_DIR=str(root / 'target'), RUSTUP_TOOLCHAIN='1.98.1')
        consumer, crates = helper.package(root, env, fixture_name='keccak-batch')
        helper.run(['cargo', '+1.98.1', 'generate-lockfile', '--offline'], consumer, env)
        source = consumer / 'src/main.rs'
        original = source.read_text()
        negatives = []
        for owner in ('Authority', "Session<'static>", "Executor<'static>"):
            for trait in ('Send', 'Sync', 'Copy', 'Clone', 'std::fmt::Debug'):
                negatives.append((f'fn need<T: {trait}>() {{}} need::<brynja_hash_sha3::batch::{owner}>();', 'E0277'))
        for trait in ('Send', 'Sync', 'Copy', 'Clone', 'std::fmt::Debug'):
            negatives.append((f'fn need<T: {trait}>() {{}} need::<Authority>();', 'E0277'))
        negatives.extend((
            ('let _ = brynja_hash_sha3::batch::Authority::from_platform(brynja_hash_sha3::batch::Kernel::Avx2, |_| true);', 'E0133'),
            ("fn escape(a: brynja_hash_sha3::batch::Authority) -> brynja_hash_sha3::batch::Session<'static> { a.session().unwrap() }", 'E0515'),
            ('fn bad(e: brynja_hash_sha3::batch::Executor, i: &[Input], o: &mut [&mut [u8]], w: &mut Workspace, s: &mut [u8], c: &mut Control) { let _ = e.digest(i, o, w, s, c); }', 'E0308'),
        ))
        try:
            for code, error in negatives:
                source.write_text(original + '\nfn negative() { ' + code + ' }\n')
                result = run(['cargo', '+1.98.1', 'check', '--locked', '--offline'], consumer, env)
                if not result.returncode or f'error[{error}]' not in result.stderr:
                    raise ValueError('incorrect negative rejection: ' + result.stderr)
        finally:
            source.write_text(original)
        data, expected = differential.corpus()
        modes = ('portable', 'prefer', 'required') if native else ('portable',)
        for mode in modes:
            command = ['cargo', '+1.98.1', 'run', '--locked', '--offline', '--release', '--', mode]
            result = run(command, consumer, env, data)
            if result.returncode or result.stdout.splitlines() != expected:
                raise ValueError('packaged batch mismatch: ' + result.stderr)
        leaf = crates['brynja-hash-sha3'] / 'src/batch'
        mutations = [
            (leaf / 'engine.rs', 'output.copy_from_slice(source);', 'let _ = source;'),
            (leaf / 'engine.rs', 'output.copy_from_slice(source);', 'if let (Some(o), Some(s)) = (output.first_mut(), source.first()) { *o = *s; }'),
            (leaf / 'engine.rs', 'crate::keccak::permute(state);', 'let _ = state;'),
            (leaf / 'framing.rs', '(6, 3)', '(4, 3)'),
            (leaf / 'framing.rs', '(31, 5)', '(6, 3)'),
            (leaf / 'framing.rs', '(4, 3)', '(31, 5)'),
            (leaf / 'framing.rs', 'Part::Bits(input.name)', 'Part::Zeros(input.name.bit_len())'),
            (leaf / 'framing.rs', 'Part::Bits(input.customization)', 'Part::Zeros(input.customization.bit_len())'),
            (leaf / 'engine.rs', 'super::framing::mask(self.input.output_bits % 8)', '255'),
        ]
        if native:
            mutations.append((leaf / 'engine.rs', '.permute(PublicData::new(&mut workspace.vector))', '.ensure_healthy()'))
        for path, before, after in mutations:
            previous = path.read_text()
            if previous.count(before) != 1: raise ValueError('mutation anchor drift: ' + before)
            try:
                path.write_text(previous.replace(before, after))
                mode = 'required' if native else 'portable'
                result = run(['cargo', '+1.98.1', 'run', '--locked', '--offline', '--release', '--', mode], consumer, env, data)
                # Require a runnable mutant, not a syntax/type-error substitute.
                if result.returncode: raise ValueError('mutant did not run: ' + result.stderr)
                if result.stdout.splitlines() == expected: raise ValueError('surviving mutant: ' + before)
            finally:
                path.write_text(previous)
        print(f'Packaged Keccak batch: {len(negatives)} negatives, {len(mutations)} compiled mutants rejected; modes={modes}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--native', action='store_true')
    main(parser.parse_args().native)
