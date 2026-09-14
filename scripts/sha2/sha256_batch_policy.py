"""Exact source and public-data-only policy for ordinary SHA-224/256 batching."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REVIEW = 'scripts/sha2/sha256-batch-reviewed.json'
CRATES = ('brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu', 'brynja-hash-sha2', 'brynja-crypto-cpu-std')


def paths(root=ROOT):
    result = {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'docs/sha256-batch-execution.md',
              'scripts/checks.sh', 'scripts/zeroization/check-zeroization-miri.sh',
              'scripts/zeroization/check-zeroization-sanitizer.sh', 'scripts/assurance/check-kani.sh'}
    for crate in CRATES:
        base = root / 'crates' / crate
        result.update(str(path.relative_to(root)) for path in (base / 'src').rglob('*.rs'))
        result.update(f'crates/{crate}/{name}' for name in ('Cargo.toml', 'README.md'))
    result.add('crates/brynja-hash-sha2/tests/batch.rs')
    result.update(str(path.relative_to(root)) for path in (root / 'assurance/sha256-batch').rglob('*')
                  if path.is_file() and 'target' not in path.parts and path.suffix in ('.rs', '.toml', '.lock'))
    result.update(str(path.relative_to(root)) for path in (root / 'scripts/sha2').glob('*sha256*batch*.py'))
    result.update(('scripts/sha2/check-sha2-execution.py', 'scripts/sha2/sha2_execution_faults.py',
                   'scripts/sha2/check-sha2-bit-differential.py'))
    return sorted(result)


def snapshot(root=ROOT):
    result = {}
    for name in paths(root):
        path = root / name
        if not path.is_file() or any(part.is_symlink() for part in (path, *path.parents)):
            raise ValueError('missing or symlinked source: ' + name)
        result[name] = hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()
    return result


def validate(root=ROOT):
    reviewed = json.loads((root / REVIEW).read_text())
    if set(reviewed) != {'schema', 'version', 'files'} or reviewed['schema'] != 1 or reviewed['version'] != '0.24.45':
        raise ValueError('batch review schema')
    if reviewed['files'] != snapshot(root): raise ValueError('batch source closure changed; reopen review')
    for name in ('crates/brynja-hash-sha2/src/batch', 'crates/brynja-crypto-cpu/src/sha256_batch'):
        for path in (root / name).glob('*.rs'):
            if len(path.read_text().splitlines()) >= 500: raise ValueError('oversized batch module')
    public = (root / 'crates/brynja-hash-sha2/src/batch/mod.rs').read_text()
    for token in ('public-data-only', 'does not zeroize', 'PublicData', '*output = staged;', 'Error::WorkLimit', 'Error::Cancelled'):
        if token not in public: raise ValueError('batch public/transaction contract: ' + token)
    for name in ('crates/brynja-crypto-cpu/Cargo.toml', 'crates/brynja-hash-sha2/Cargo.toml', 'crates/brynja-crypto-cpu-std/Cargo.toml'):
        if 'default = []' not in (root / name).read_text(): raise ValueError('implicit vector default')
    commands = (root / 'scripts/checks.sh').read_text().splitlines()
    for command in ('python3 scripts/sha2/check-sha256-batch.py --package',
                    'python3 scripts/sha2/check-sha256-batch-codegen.py',
                    'python3 scripts/sha2/test-sha256-batch.py',
                    'cargo clippy --locked --offline --manifest-path assurance/sha256-batch/Cargo.toml --all-targets -- -D warnings -A clippy::chunks_exact_to_as_chunks'):
        if command not in commands: raise ValueError('missing batch acceptance command')
    print('SHA-224/256 batch source/public-data policy: PASS')
