#!/usr/bin/env python3
"""Strict reviewed MD5 production and assurance boundary (not formal review)."""
import hashlib
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CRATE = 'crates/brynja-legacy-md5/'
FILES = ('compress.rs', 'engine.rs', 'hardened.rs', 'lib.rs', 'ordinary.rs', 'output.rs', 'owner.rs')
TOKENS = {
    'lib.rs': ('#![no_std]', 'collision- and chosen-prefix-broken', 'No independent cryptographic review or FIPS validation'),
    'engine.rs': ('current: u128', 'current.checked_add(additional)', 'bytes.checked_mul(8)', 'admit_bytes(owner.bits(), input.len())?', 'admit_bits(owner.bits(), additional)?', 'tail.split()', 'if offset >= 56', '.zip([0, 8, 16, 24, 32, 40, 48, 56])', 'rfc_length_wrap_is_not_sha1_exhaustion', 'padding_encodes_low_64_bits_only_in_little_endian_order'),
    'ordinary.rs': ('pub fn finalize(mut self)', 'pub fn finalize_bits(mut self,', 'pub fn md5(', 'pub fn md5_bits('),
    'hardened.rs': ('pub trait HardenedMd5State: sealed::Sealed', 'pub struct HardenedMd5', 'mut self,', 'output::failed(destination, error)', 'output::secret(&self.owner.output_staging, destination)'),
    'owner.rs': ('impl Drop for Md5Owner', 'self.wipe();', '#[inline(never)]'),
    'compress.rs': ('CONSTANTS: [u32; 64]', 'CONSTANTS.into_iter().enumerate()', '.rotate_left(shift).wrapping_add(b)', '.zip([0, 8, 16, 24])', 'owner.clear_block();'),
}
REGIONS = ('chaining_state', 'block', 'message_length', 'buffered', 'output_staging')
BOUND = [CRATE + 'src/' + name for name in FILES] + [
    CRATE + 'Cargo.toml', CRATE + 'README.md', CRATE + 'tests/api.rs', CRATE + 'tests/vectors/rfc1321.txt',
    'assurance/md5-public-api/Cargo.toml', 'assurance/md5-public-api/Cargo.lock',
    'assurance/md5-public-api/src/lib.rs', 'assurance/md5-public-api/src/main.rs',
    'scripts/md5/check-md5-differential.py', 'scripts/md5/check-md5-codegen.sh',
    'scripts/md5/check-md5-package.py',
    'scripts/md5/check-md5.py',
]


def validate_vectors(rfc: str, vectors: str):
    pairs = re.findall(r'^MD5 \("([^"]*)"\) =\s*([0-9a-f]{32})', rfc, re.M)
    expected = []
    for message, digest in pairs:
        data = message.replace('\n', '').encode('ascii')
        expected.append(f'{len(data) * 8}|{data.hex() or "-"}|{digest}')
    actual = [line for line in vectors.splitlines() if line and not line.startswith('#')]
    if len(expected) != 7 or actual != expected:
        raise ValueError('MD5 vectors differ from pinned RFC 1321 appendix A.5')


def validate(root=ROOT, hashes=True):
    src = root / CRATE / 'src'
    if sorted(path.name for path in src.glob('*.rs')) != sorted(FILES):
        raise ValueError('MD5 source inventory differs')
    for name in FILES:
        text = (src / name).read_text()
        if len(text.splitlines()) > 500:
            raise ValueError('MD5 source exceeds 500 lines')
        for token in TOKENS.get(name, ()):
            if re.sub(r'\s+', '', token) not in re.sub(r'\s+', '', text):
                raise ValueError(f'MD5 contract missing: {name}: {token}')
        production = text.split('#[cfg(test)]')[0].split('#[cfg(kani)]')[0]
        if re.search(r'\b(unsafe\s*\{|extern|alloc::|std::|Vec|Box|static\s+mut)|\.(unwrap|expect)\(|\b(panic|unimplemented|todo)!', production):
            raise ValueError('MD5 unsafe, hosted or panic surface')
    owner = (src / 'owner.rs').read_text()
    if '#[cfg(debug_assertions)]' in (src / 'engine.rs').read_text():
        raise ValueError('MD5 invariant regression tests must also run in release')
    engine = re.sub(r'\s+', '', (src / 'engine.rs').read_text().split('#[cfg(test)]')[0])
    for operation in ('update', 'padding'):
        guard = re.sub(r'\s+', '', f'assert!(offset < owner.block.len(), "MD5 {operation} offset invariant");')
        if 'debug_'+guard in engine:
            raise ValueError('MD5 buffer guard must remain active in release')
        if engine.count(guard + 'ifletSome(destination)=owner.block.get_mut(offset)') != 1:
            raise ValueError(f'MD5 {operation} buffer invariant guard missing or misplaced')
    for region in REGIONS:
        if f'clear_owned_region(&mut self.{region})' not in owner:
            raise ValueError('MD5 private region is not cleared')
    manifest = tomllib.loads((root / CRATE / 'Cargo.toml').read_text())
    if set(manifest['dependencies']) != {'brynja-core', 'brynja-hash-core'} or manifest['features'] != {'default': []}:
        raise ValueError('MD5 dependency or feature boundary')
    checker = (root / 'scripts/md5/check-md5.py').read_text()
    for token in ("'--release'", "'--lib', 'invalid_'", 'check=True', 'timeout=120'):
        if token not in checker:
            raise ValueError('MD5 optimized invariant tests must remain in the gate')
    for path, token in (
        ('scripts/checks.sh', 'python3 scripts/md5/check-md5.py'),
        ('scripts/zeroization/check-zeroization-miri.sh', 'run_miri -p brynja-legacy-md5'),
        ('scripts/zeroization/check-zeroization-sanitizer.sh', '-p brynja-legacy-md5'),
        ('scripts/ci/check-rust-version-matrix.sh', 'assurance/md5-public-api/Cargo.toml'),
        ('scripts/assurance/check-bare-metal.sh', 'assurance/md5-public-api/Cargo.toml'),
        ('scripts/assurance/check-kani.sh', 'cargo kani -p brynja-legacy-md5'),
    ):
        if token not in (root / path).read_text(): raise ValueError(f'MD5 gate missing: {path}')
    if hashes:
        rfc = (root / 'rfc/rfc1321.txt').read_bytes()
        if hashlib.sha256(rfc).hexdigest() != '284a79d148400d9cd2a423211d1103b5cef0fb9256a4cbe6d7ebe5197c3149dd':
            raise ValueError('MD5 normative RFC bytes changed')
        validate_vectors(rfc.decode('ascii'), (root / CRATE / 'tests/vectors/rfc1321.txt').read_text())
        expected = tomllib.loads((root / 'scripts/md5/md5-reviewed.toml').read_text())['sha256']
        if set(expected) != set(BOUND): raise ValueError('MD5 reviewed inventory differs')
        for path in BOUND:
            if hashlib.sha256((root / path).read_bytes()).hexdigest() != expected[path]:
                raise ValueError(f'MD5 reviewed source changed: {path}')


def inventory():
    return '[sha256]\n' + ''.join(f'"{path}" = "{hashlib.sha256((ROOT / path).read_bytes()).hexdigest()}"\n' for path in BOUND)
