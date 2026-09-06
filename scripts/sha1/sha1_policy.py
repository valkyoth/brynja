#!/usr/bin/env python3
"""Strict reviewed SHA-1 production and assurance boundary (not formal review)."""
import hashlib
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CRATE = 'crates/brynja-legacy-sha1/'
FILES = ('compress.rs', 'engine.rs', 'hardened.rs', 'lib.rs', 'ordinary.rs', 'output.rs', 'owner.rs')
TOKENS = {
    'lib.rs': ('#![no_std]', 'collision-broken', 'No independent cryptographic review or FIPS validation'),
    'engine.rs': ('current.checked_add(additional)', 'bytes.checked_mul(8)', 'admit_bytes(owner.bits(), input.len())?', 'admit_bits(owner.bits(), additional)?', 'tail.split()', 'if offset >= 56'),
    'ordinary.rs': ('pub fn finalize(mut self)', 'pub fn finalize_bits(mut self,', 'pub fn sha1(', 'pub fn sha1_bits('),
    'hardened.rs': ('pub trait HardenedSha1State: sealed::Sealed', 'pub struct HardenedSha1', 'mut self,', 'output::failed(destination, error)', 'output::secret(&self.owner.output_staging, destination)'),
    'owner.rs': ('impl Drop for Sha1Owner', 'self.wipe();', '#[inline(never)]'),
    'compress.rs': ('16_usize..80', '.rotate_left(1)', '0..80', '.rotate_left(5)', 'b.rotate_left(30)', 'owner.clear_block();'),
}
REGIONS = ('chaining_state', 'block', 'schedule', 'message_length', 'buffered', 'output_staging')
BOUND = [CRATE + 'src/' + name for name in FILES] + [
    CRATE + 'Cargo.toml', CRATE + 'README.md', CRATE + 'tests/api.rs', CRATE + 'tests/vectors/nist.txt',
    'assurance/sha1-public-api/Cargo.toml', 'assurance/sha1-public-api/Cargo.lock',
    'assurance/sha1-public-api/src/lib.rs', 'assurance/sha1-public-api/src/main.rs',
    'scripts/sha1/check-sha1-differential.py', 'scripts/sha1/check-sha1-codegen.sh',
    'scripts/sha1/check-sha1-package.py',
    'scripts/sha1/check-sha1.py',
]


def validate(root=ROOT, hashes=True):
    src = root / CRATE / 'src'
    if sorted(path.name for path in src.glob('*.rs')) != sorted(FILES):
        raise ValueError('SHA-1 source inventory differs')
    for name in FILES:
        text = (src / name).read_text()
        if len(text.splitlines()) > 500:
            raise ValueError('SHA-1 source exceeds 500 lines')
        for token in TOKENS.get(name, ()):
            if re.sub(r'\s+', '', token) not in re.sub(r'\s+', '', text):
                raise ValueError(f'SHA-1 contract missing: {name}: {token}')
        production = text.split('#[cfg(test)]')[0].split('#[cfg(kani)]')[0]
        if re.search(r'\b(unsafe\s*\{|extern|alloc::|std::|Vec|Box|static\s+mut)|\.(unwrap|expect)\(|\b(panic|unimplemented|todo)!', production):
            raise ValueError('SHA-1 unsafe, hosted or panic surface')
    owner = (src / 'owner.rs').read_text()
    if '#[cfg(debug_assertions)]' in (src / 'engine.rs').read_text():
        raise ValueError('SHA-1 invariant regression tests must also run in release')
    engine = re.sub(r'\s+', '', (src / 'engine.rs').read_text().split('#[cfg(test)]')[0])
    for operation in ('update', 'padding'):
        guard = re.sub(r'\s+', '', f'assert!(offset < owner.block.len(), "SHA-1 {operation} offset invariant");')
        if 'debug_' + guard in engine:
            raise ValueError('SHA-1 buffer guard must remain active in release')
        if engine.count(guard + 'ifletSome(destination)=owner.block.get_mut(offset)') != 1:
            raise ValueError(f'SHA-1 {operation} buffer invariant guard missing or misplaced')
    for region in REGIONS:
        if f'clear_owned_region(&mut self.{region})' not in owner:
            raise ValueError('SHA-1 private region is not cleared')
    manifest = tomllib.loads((root / CRATE / 'Cargo.toml').read_text())
    if set(manifest['dependencies']) != {'brynja-core', 'brynja-hash-core'} or manifest['features'] != {'default': [], 'cpu': []}:
        raise ValueError('SHA-1 dependency or feature boundary')
    for path, token in (
        ('scripts/sha1/check-sha1.py', "'--release'"),
        ('scripts/sha1/check-sha1.py', "'--lib', 'invalid_'"),
        ('scripts/sha1/check-sha1.py', 'check=True'),
        ('scripts/sha1/check-sha1.py', 'timeout=120'),
        ('scripts/checks.sh', 'python3 scripts/sha1/check-sha1.py'),
        ('scripts/zeroization/check-zeroization-miri.sh', 'run_miri -p brynja-legacy-sha1'),
        ('scripts/zeroization/check-zeroization-sanitizer.sh', '-p brynja-legacy-sha1'),
        ('scripts/ci/check-rust-version-matrix.sh', 'assurance/sha1-public-api/Cargo.toml'),
        ('scripts/assurance/check-bare-metal.sh', 'assurance/sha1-public-api/Cargo.toml'),
        ('scripts/assurance/check-kani.sh', 'cargo kani -p brynja-legacy-sha1'),
    ):
        if token not in (root / path).read_text(): raise ValueError(f'SHA-1 gate missing: {path}')
    if hashes:
        expected = tomllib.loads((root / 'scripts/sha1/reviewed.toml').read_text())['sha256']
        if set(expected) != set(BOUND): raise ValueError('SHA-1 reviewed inventory differs')
        for path in BOUND:
            if hashlib.sha256((root / path).read_bytes()).hexdigest() != expected[path]:
                raise ValueError(f'SHA-1 reviewed source changed: {path}')


def inventory():
    return '[sha256]\n' + ''.join(f'"{path}" = "{hashlib.sha256((ROOT / path).read_bytes()).hexdigest()}"\n' for path in BOUND)
