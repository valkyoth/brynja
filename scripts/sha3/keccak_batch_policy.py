"""Reviewed ordinary Keccak batch source and assurance inventory."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REVIEW = 'scripts/sha3/keccak-batch-reviewed.json'
CRATES = ('brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu', 'brynja-hash-sha2',
          'brynja-hash-sha3', 'brynja-crypto-cpu-std')
CONTRACTS = {
    'docs/keccak-batch-execution.md': (
        'PublicData` is a caller assertion, not provenance enforcement or declassification.',
        'Review every new `PublicData::new` call site for public provenance.',
        'With `panic = "abort"`, Drop does not run and quarantine is not promised.',
        'Cached detection is not live revocation.',
        'QEMU is explicitly not native evidence.'),
    'crates/brynja-hash-sha3/src/batch/tests.rs': (
        'Some(report.vector_calls)', 'Session::completed_vector_calls', '!b'),
    'crates/brynja-crypto-cpu/src/keccak_batch/mod.rs': (
        'Revalidation is not a scheduler lock or a live migration monitor.',
        'If this cannot be guaranteed, use portable execution instead.'),
    'crates/brynja-crypto-cpu/src/keccak_batch/platform.rs': (
        'immediately before dispatch cannot prevent intervening migration.',
        'CPU affinity may constrain scheduling but does not prove VM-host support.'),
    'crates/brynja-hash-sha3/src/batch/mod.rs': (
        'Never use this workspace for keyed or otherwise secret-derived state.',
        'It is not a hardened owner; a clearing wrapper cannot erase kernel copies.'),
}
COMMANDS = {
    'scripts/checks.sh': (
        'python3 scripts/sha3/check-keccak-batch.py',
        'python3 scripts/sha3/test-keccak-batch-package.py',
        'python3 scripts/sha3/check-keccak-batch-codegen.py',
        'python3 scripts/sha3/test-keccak-batch-codegen.py',
        'python3 scripts/sha3/test-keccak-batch-asan.py',
        'python3 scripts/sha3/test-keccak-batch-policy.py',
        'python3 scripts/sha3/test-keccak-batch-native.py',
        'cargo test --locked --offline --manifest-path assurance/keccak-batch/Cargo.toml',
        'cargo clippy --locked --offline --manifest-path assurance/keccak-batch/Cargo.toml --all-targets -- -D warnings -A clippy::chunks_exact_to_as_chunks'),
    'scripts/zeroization/check-zeroization-sanitizer.sh': ('python3 scripts/sha3/check-keccak-batch-asan.py',),
    'scripts/zeroization/check-zeroization-miri.sh': (
        'run_miri -p brynja-hash-sha3 --features batch-execution --lib batch::tests::shape_staging_empty_and_scalar_tail_boundaries',
        'run_miri -p brynja-hash-sha3 --features batch-execution --lib batch::tests::bounded_batch_lifecycle'),
    'scripts/assurance/check-kani.sh': (
        'rustup run "$kani_toolchain" cargo kani -p brynja-hash-sha3 --features batch-execution --harness batch::control::proofs::batch_budget_is_atomic_and_never_wraps',),
}


def paths(root=ROOT):
    names = {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'docs/keccak-batch-execution.md',
             *COMMANDS, 'scripts/zeroization/miri_scope.py',
             'scripts/sha3/check-sha3-bit-differential.py', 'scripts/sha3/check-cshake-differential.py',
             'scripts/sha2/check-sha2-execution.py', 'scripts/sha2/sha2_execution_faults.py'}
    for crate in CRATES:
        base = root / 'crates' / crate
        names.update(str(p.relative_to(root)) for p in (base / 'src').rglob('*.rs'))
        names.update(f'crates/{crate}/{name}' for name in ('Cargo.toml', 'README.md'))
    names.update(str(p.relative_to(root)) for p in (root / 'assurance/keccak-batch').rglob('*')
                 if p.is_file() and 'target' not in p.parts and p.suffix in ('.rs', '.toml', '.lock'))
    names.update(str(p.relative_to(root)) for p in (root / 'scripts/sha3').glob('*keccak*batch*.py'))
    # Pinned official bytes used to cross-check the independent oracle.
    names.add('crates/brynja-hash-sha3/tests/vectors/nist-bit-selected.txt')
    return sorted(names)


def snapshot(root=ROOT):
    result = {}
    for name in paths(root):
        path = root / name
        if not path.is_file() or any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('missing/symlinked batch source: ' + name)
        result[name] = hashlib.sha512(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()
    return result


def validate_separation(root=ROOT):
    # An integration tripwire for the existing hardened module, not a Rust
    # provenance proof. The full source closure additionally requires review.
    base = root / 'crates/brynja-hash-sha3/src/hardened'
    sources = sorted(base.rglob('*.rs'))
    if not sources: raise ValueError('missing hardened SHA-3 source')
    for path in sources:
        code = '\n'.join(line.split('//')[0] for line in path.read_text().splitlines())
        if re.search(r'\b(?:batch|keccak_batch)\b', code):
            raise ValueError('ordinary batching referenced by hardened SHA-3: ' + str(path))


def validate_contracts(root=ROOT):
    validate_separation(root)
    for name, tokens in CONTRACTS.items():
        text = (root / name).read_text()
        for token in tokens:
            if token not in text: raise ValueError('missing batch contract: ' + token)
    for name, commands in COMMANDS.items():
        lines = [line.strip() for line in (root / name).read_text().splitlines()]
        for command in commands:
            if lines.count(command) != 1: raise ValueError('missing/ambiguous batch assurance command: ' + command)
    for crate in ('brynja-crypto-cpu', 'brynja-hash-sha3', 'brynja-crypto-cpu-std'):
        if 'default = []' not in (root / 'crates' / crate / 'Cargo.toml').read_text():
            raise ValueError('batch feature must remain default-off')


def validate(root=ROOT):
    review = json.loads((root / REVIEW).read_text())
    if set(review) != {'schema', 'version', 'files'} or type(review['schema']) is not int or review['schema'] != 1 or review['version'] != '0.24.47':
        raise ValueError('Keccak batch review schema')
    if review['files'] != snapshot(root): raise ValueError('Keccak batch source closure changed; reopen review')
    validate_contracts(root)
    print('Keccak batch source/public-data and assurance policy: PASS')
