#!/usr/bin/env python3
"""Reject structural MD5 regressions even when a source hash is refreshed."""
import shutil
import tempfile
from pathlib import Path
import md5_policy as policy


def main():
    policy.validate()
    rfc = (policy.ROOT / 'rfc/rfc1321.txt').read_text()
    vectors = (policy.ROOT / policy.CRATE / 'tests/vectors/rfc1321.txt').read_text()
    for broken in (vectors.replace('d41d8cd98f00b204e9800998ecf8427e', '0' * 32),
                   '\n'.join(vectors.splitlines()[:-1])):
        try: policy.validate_vectors(rfc, broken)
        except ValueError: continue
        raise AssertionError('accepted corrupt or incomplete RFC vector selection')
    mutations = [
        (policy.CRATE + 'src/engine.rs', 'current: u128', 'current: u64'),
        (policy.CRATE + 'src/engine.rs', '.zip([0, 8, 16, 24, 32, 40, 48, 56])', '.zip([56, 48, 40, 32, 24, 16, 8, 0])'),
        (policy.CRATE + 'src/engine.rs', '.checked_add(additional)', '.wrapping_add(additional)'),
        (policy.CRATE + 'src/engine.rs', 'if offset >= 56', 'if offset > 56'),
        (policy.CRATE + 'src/engine.rs', 'debug_assert!(offset < owner.block.len(), "MD5 update offset invariant");', ''),
        (policy.CRATE + 'src/engine.rs', 'debug_assert!(offset < owner.block.len(), "MD5 padding offset invariant");', ''),
        (policy.CRATE + 'src/engine.rs', 'offset < owner.block.len()', 'offset <= owner.block.len()'),
        (policy.CRATE + 'src/engine.rs',
         'debug_assert!(offset < owner.block.len(), "MD5 update offset invariant");\n        if let Some(destination) = owner.block.get_mut(offset) {',
         'if let Some(destination) = owner.block.get_mut(offset) {\n            debug_assert!(offset < owner.block.len(), "MD5 update offset invariant");'),
        (policy.CRATE + 'src/ordinary.rs', 'pub fn finalize(mut self)', 'pub fn finalize(&mut self)'),
        (policy.CRATE + 'src/hardened.rs', 'HardenedMd5State: sealed::Sealed', 'HardenedMd5State'),
        (policy.CRATE + 'src/compress.rs', '.rotate_left(shift)', '.rotate_right(shift)'),
        (policy.CRATE + 'src/lib.rs', '#![no_std]', ''),
        (policy.CRATE + 'src/output.rs', 'use brynja_core', 'extern crate alloc;\nuse brynja_core'),
        ('scripts/zeroization/check-zeroization-miri.sh', 'run_miri -p brynja-legacy-md5', 'run_miri -p brynja-core'),
        ('scripts/zeroization/check-zeroization-sanitizer.sh', '-p brynja-legacy-md5', '-p brynja-core'),
    ] + [(policy.CRATE + 'src/owner.rs', f'clear_owned_region(&mut self.{region})', f'Ok(self.{region}.fill(0))') for region in policy.REGIONS]
    for path, before, after in mutations:
        with tempfile.TemporaryDirectory(prefix='brynja-md5-policy-') as directory:
            root = Path(directory)
            shutil.copytree(policy.ROOT / policy.CRATE, root / policy.CRATE)
            for source in ('scripts/checks.sh', 'scripts/zeroization/check-zeroization-miri.sh',
                           'scripts/zeroization/check-zeroization-sanitizer.sh', 'scripts/ci/check-rust-version-matrix.sh',
                           'scripts/assurance/check-bare-metal.sh', 'scripts/assurance/check-kani.sh'):
                target = root / source
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(policy.ROOT / source, target)
            target = root / path
            text = target.read_text()
            assert before in text, before
            target.write_text(text.replace(before, after))
            try: policy.validate(root, hashes=False)
            except ValueError: continue
            raise AssertionError(f'accepted MD5 regression: {path}: {before}')
    print(f'MD5 source policy rejects {len(mutations)} structural regressions')


if __name__ == '__main__': main()
