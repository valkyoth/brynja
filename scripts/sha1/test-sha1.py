#!/usr/bin/env python3
"""Reject structural SHA-1 regressions even when a source hash is refreshed."""
import shutil
import tempfile
from pathlib import Path
import sha1_policy as policy


def main():
    policy.validate()
    mutations = [
        ('scripts/sha1/check-sha1.py', "'--release',", ''),
        ('scripts/sha1/check-sha1.py', "'--lib', 'invalid_'", "'--lib', 'unmatched_filter'"),
        (policy.CRATE + 'src/engine.rs', 'fn invalid_update_offsets_trip_before_mutation()', '#[cfg(debug_assertions)]\n    fn invalid_update_offsets_trip_before_mutation()'),
        (policy.CRATE + 'src/engine.rs', 'fn invalid_padding_offsets_trip_before_mutation()', '#[cfg(debug_assertions)]\n    fn invalid_padding_offsets_trip_before_mutation()'),
        (policy.CRATE + 'src/engine.rs', 'assert!(offset < owner.block.len(), "SHA-1 update offset invariant");', 'debug_assert!(offset < owner.block.len(), "SHA-1 update offset invariant");'),
        (policy.CRATE + 'src/engine.rs', 'assert!(offset < owner.block.len(), "SHA-1 padding offset invariant");', 'debug_assert!(offset < owner.block.len(), "SHA-1 padding offset invariant");'),
        (policy.CRATE + 'src/engine.rs', '.checked_add(additional)', '.wrapping_add(additional)'),
        (policy.CRATE + 'src/engine.rs', 'if offset >= 56', 'if offset > 56'),
        (policy.CRATE + 'src/engine.rs', 'assert!(offset < owner.block.len(), "SHA-1 update offset invariant");', ''),
        (policy.CRATE + 'src/engine.rs', 'assert!(offset < owner.block.len(), "SHA-1 padding offset invariant");', ''),
        (policy.CRATE + 'src/engine.rs', 'offset < owner.block.len()', 'offset <= owner.block.len()'),
        (policy.CRATE + 'src/engine.rs',
         'assert!(offset < owner.block.len(), "SHA-1 update offset invariant");\n        if let Some(destination) = owner.block.get_mut(offset) {',
         'if let Some(destination) = owner.block.get_mut(offset) {\n            assert!(offset < owner.block.len(), "SHA-1 update offset invariant");'),
        (policy.CRATE + 'src/ordinary.rs', 'pub fn finalize(mut self)', 'pub fn finalize(&mut self)'),
        (policy.CRATE + 'src/hardened.rs', 'HardenedSha1State: sealed::Sealed', 'HardenedSha1State'),
        (policy.CRATE + 'src/compress.rs', 'b.rotate_left(30)', 'b.rotate_left(29)'),
        (policy.CRATE + 'src/lib.rs', '#![no_std]', ''),
        (policy.CRATE + 'src/output.rs', 'use brynja_core', 'extern crate alloc;\nuse brynja_core'),
        ('scripts/zeroization/check-zeroization-miri.sh', 'run_miri -p brynja-legacy-sha1', 'run_miri -p brynja-core'),
        ('scripts/zeroization/check-zeroization-sanitizer.sh', '-p brynja-legacy-sha1', '-p brynja-core'),
    ] + [(policy.CRATE + 'src/owner.rs', f'clear_owned_region(&mut self.{region})', f'Ok(self.{region}.fill(0))') for region in policy.REGIONS]
    for path, before, after in mutations:
        with tempfile.TemporaryDirectory(prefix='brynja-sha1-policy-') as directory:
            root = Path(directory)
            shutil.copytree(policy.ROOT / policy.CRATE, root / policy.CRATE)
            for source in ('scripts/checks.sh', 'scripts/zeroization/check-zeroization-miri.sh',
                           'scripts/zeroization/check-zeroization-sanitizer.sh', 'scripts/ci/check-rust-version-matrix.sh',
                           'scripts/assurance/check-bare-metal.sh', 'scripts/assurance/check-kani.sh',
                           'scripts/sha1/check-sha1.py'):
                target = root / source
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(policy.ROOT / source, target)
            target = root / path
            text = target.read_text()
            assert before in text, before
            target.write_text(text.replace(before, after))
            try: policy.validate(root, hashes=False)
            except ValueError: continue
            raise AssertionError(f'accepted SHA-1 regression: {path}: {before}')
    print(f'SHA-1 source policy rejects {len(mutations)} structural regressions')


if __name__ == '__main__': main()
