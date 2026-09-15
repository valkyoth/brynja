#!/usr/bin/env python3
"""Hash, feature-default and semantic assurance regressions for Keccak batching."""
import contextlib
import io
from pathlib import Path
import shutil
import tempfile
import keccak_batch_policy as policy


def reject(call):
    try: call()
    except (ValueError, FileNotFoundError): return
    raise AssertionError('regression was accepted')


def main():
    count = 0
    with tempfile.TemporaryDirectory(prefix='brynja-keccak-batch-policy-') as directory, contextlib.redirect_stdout(io.StringIO()):
        root = Path(directory)
        for name in (*policy.paths(), policy.REVIEW):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(policy.ROOT / name, target)
        policy.validate(root)
        for name, tokens in (*policy.CONTRACTS.items(), *policy.COMMANDS.items()):
            target = root / name
            original = target.read_text()
            for token in tokens:
                target.write_text(original.replace(token, ''))
                reject(lambda: policy.validate_contracts(root))
                target.write_text(original)
                count += 1
        for crate in ('brynja-crypto-cpu', 'brynja-hash-sha3', 'brynja-crypto-cpu-std'):
            target = root / 'crates' / crate / 'Cargo.toml'
            original = target.read_text()
            target.write_text(original.replace('default = []', 'default = ["unreviewed"]'))
            reject(lambda: policy.validate_contracts(root))
            target.write_text(original)
            count += 1
        for name in ('crates/brynja-crypto-cpu/src/keccak_batch/x86.rs',
                     'crates/brynja-crypto-cpu/src/keccak_batch/arm.rs',
                     'crates/brynja-hash-sha3/src/batch/engine.rs',
                     'crates/brynja-crypto-cpu-std/src/keccak_batch/platform.rs',
                     'assurance/keccak-batch/src/benchmark.rs', 'scripts/checks.sh'):
            target = root / name
            original = target.read_bytes()
            target.write_bytes(original + b'\nchanged\n')
            reject(lambda: policy.validate(root))
            target.write_bytes(original)
            count += 1
        target = root / 'crates/brynja-crypto-cpu/src/keccak_batch/x86.rs'
        original = target.read_bytes()
        target.unlink()
        reject(lambda: policy.validate(root))
        target.symlink_to(policy.ROOT / 'crates/brynja-crypto-cpu/src/keccak_batch/x86.rs')
        reject(lambda: policy.validate(root))
        target.unlink()
        target.write_bytes(original)
        target = root / 'crates/brynja-hash-sha3/src/batch/unreviewed.rs'
        target.write_text('// new source\n')
        reject(lambda: policy.validate(root))
        count += 3
    print(f'Keccak batch policy rejects {count} hash/contract/command/default/removal/symlink/new-source regressions')


if __name__ == '__main__': main()
