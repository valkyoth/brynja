#!/usr/bin/env python3
"""Development-only compiled scheduled-batch regressions, not native qualification."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def run(command, root, env, success=True):
    result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=300)
    if success and result.returncode:
        raise RuntimeError(str(command) + '\n' + result.stdout[-2000:] + result.stderr[-2000:])
    return result


def campaign(root, env, cargo, target):
    command = [*cargo, 'test', '--locked', '--offline', '-p', 'brynja-hash-parallel',
               '--features', 'hardened-batch-execution', '--target', target, '--lib', 'execution::batch']
    run(command, root, env)
    run(command[:-2] + ['--doc', 'execution::batch'], root, env)
    base = 'crates/brynja-hash-parallel/src/execution/'
    cases = [
        (base + 'batch.rs', 'clear_owned_region(self.values.as_flattened_mut())', 'Ok::<(), ()>(())', 'completed_owner'),
        (base + 'batch.rs', 'clear_owned_region(&mut self.staging)', 'Ok::<(), ()>(())', 'completed_owner'),
        (base + 'batch.rs', 'self.clear();\n        #[cfg(test)]', '// omitted Drop clear\n        #[cfg(test)]', 'completed_owner'),
        (base + 'batch.rs', 'WorkerPolicy::RequireAcceleration if kernel.is_none()', 'WorkerPolicy::RequireAcceleration if false', 'worker_policy'),
        (base + 'collector/batch.rs', '!core::ptr::eq(plan, leaves.plan)', 'false', 'provenance_order'),
        (base + 'collector/batch.rs', 'leaves.start != root.merged_leaves()', 'false', 'provenance_order'),
        (base + 'collector/batch.rs', 'let plan = root.binding.scheduled()?;', 'let plan = leaves.plan;', 'scheduled_tokens'),
        (base + 'collector/batch.rs', 'root.state\n                .update(leaves.inner.expose(index).ok_or(RootError::State)?)?;\n            root.merged', '// omitted root CV absorption\n            root.merged', 'portable_domains'),
        (base + 'batch.rs', 'hash::Algorithm::Shake256', 'hash::Algorithm::Shake128', 'portable_domains'),
        (base + 'collector.rs', 'if !self.complete {', 'if false {', 'cancellation_budget'),
        (base + 'collector/batch.rs', '.checked_add(work.vector_calls)', '.checked_add(0)', 'vector_domains'),
        ('crates/brynja-hash-sha3/src/hardened_batch/engine.rs', 'report.accelerated_slots |=', 'report.accelerated_slots &=', 'vector_domains'),
    ]
    for name, before, after, test in cases:
        path = root / name
        original = path.read_text()
        if original.count(before) != 1:
            raise ValueError('ambiguous mutation anchor: ' + before)
        try:
            path.write_text(original.replace(before, after))
            result = run(command[:-1] + ['execution::batch::tests::' + test], root, env, success=False)
            if result.returncode == 0 or 'test result: FAILED' not in result.stdout:
                raise ValueError('mutant survived or failed to compile: ' + before + '\n' + result.stdout[-1500:] + result.stderr[-1500:])
        finally:
            path.write_text(original)
    run(command, root, env)
    print(f'Scheduled ParallelHash batching: {len(cases)} compiled regressions rejected')


def stream_campaign(root, env, cargo, target):
    command = [*cargo, 'test', '--locked', '--offline', '-p', 'brynja-hash-parallel',
               '--features', 'hardened-batch-execution', '--target', target, '--lib', 'execution::stream::batch']
    run(command, root, env)
    run(command[:-2] + ['--doc', 'execution::stream::batch'], root, env)
    base = 'crates/brynja-hash-parallel/src/execution/'
    path = base + 'stream/batch.rs'
    cases = [
        (path, 'self.hash.clear();\n        let _ = clear_owned_region(self.workspace);', 'self.hash.clear();', 'cancellation_budget'),
        (path, 'let _ = clear_owned_region(&mut self.input_bits);', '// omitted length cleanup', 'cancellation_budget'),
        (path, 'fn drop(&mut self) {\n        self.cancel();', 'fn drop(&mut self) {\n        // omitted drop cleanup', 'cancellation_budget'),
        (path, 'if !self.complete {', 'if false {', 'cancellation_budget'),
        (path, 'self.used()? != 0 ||', 'false ||', 'exact_completion'),
        (path, 'self.root.merged_leaves() != self.expected(self.input_bits())?', 'false', 'exact_completion'),
        (path, 'stream.check_complete()?;', '// omitted completion proof', 'exact_completion'),
        (path, 'guard.stream.input_bits = total.to_le_bytes();', '// omitted input accounting', 'portable_chunk'),
        (path, 'if self.expected(total)? > self.limit {', 'if false {', 'construction_work_limit'),
        (path, 'guard.stream.update_inner(input, control)?;', 'guard.stream.update_inner(&[], control)?;', 'portable_chunk'),
        (base + 'collector/batch.rs', 'root.accelerated = accelerated.to_le_bytes();\n        guard.complete', 'root.accelerated = [0; 16];\n        guard.complete', 'vector_chunk'),
        (base + 'collector/batch.rs', 'for index in 0..count {', 'for index in 0..0 {', 'portable_chunk'),
    ]
    for name, before, after, test in cases:
        subject = root / name
        original = subject.read_text()
        if original.count(before) != 1:
            raise ValueError('ambiguous stream mutation: ' + before)
        try:
            subject.write_text(original.replace(before, after))
            result = run(command[:-1] + ['execution::stream::batch::tests::' + test], root, env, success=False)
            if result.returncode == 0 or 'test result: FAILED' not in result.stdout:
                raise ValueError('stream mutant survived or failed to compile: ' + before + '\n' + result.stdout[-1000:] + result.stderr[-1500:])
        finally:
            subject.write_text(original)
    run(command, root, env)
    print(f'Streaming ParallelHash batching: {len(cases)} compiled regressions rejected')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', default='x86_64-unknown-linux-gnu')
    parser.add_argument('--toolchain', default='1.98.1')
    parser.add_argument('--stream', action='store_true')
    args = parser.parse_args()
    if not args.target.startswith(('x86_64-', 'aarch64-')):
        raise ValueError('unsupported architecture')
    with tempfile.TemporaryDirectory(prefix='brynja-parallelhash-batch-') as directory:
        root = Path(directory)
        for package in ('brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu', 'brynja-hash-sha2',
                        'brynja-hash-sha3', 'brynja-crypto-cpu-std', 'brynja-hash-parallel'):
            shutil.copytree(ROOT / 'crates' / package, root / 'crates' / package,
                            ignore=shutil.ignore_patterns('target'))
        (root / 'Cargo.toml').write_text((ROOT / 'Cargo.toml').read_text().replace(
            'default-members = ["crates/brynja"]', 'default-members = ["crates/brynja-hash-parallel"]'))
        env = dict(os.environ, CARGO_TARGET_DIR=str(root / 'target'))
        for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
            env.pop(key, None)
        env['RUSTFLAGS'] = '-C target-feature=' + ('+avx,+avx2' if args.target.startswith('x86_64') else '+neon')
        if args.target == 'aarch64-unknown-linux-musl':
            env['RUSTFLAGS'] += ' -C linker=rust-lld'
        env['RUSTDOCFLAGS'] = env['RUSTFLAGS']
        env['BRYNJA_REQUIRE_PARALLELHASH_BATCH'] = '1'
        cargo = ['cargo', '+' + args.toolchain]
        run([*cargo, 'generate-lockfile', '--offline'], root, env)
        (stream_campaign if args.stream else campaign)(root, env, cargo, args.target)


if __name__ == '__main__':
    main()
