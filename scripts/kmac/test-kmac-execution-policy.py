#!/usr/bin/env python3
"""Rehash-resistant mutation checks for the keyed accelerated boundary."""
import shutil
import tempfile
from pathlib import Path
import kmac_execution_policy as policy


def main():
    policy.semantic(policy.ROOT)
    cases = [(policy.SOURCE + name, token, 'REMOVED')
             for name, tokens in policy.TOKENS.items() for token in tokens]
    cases += [(policy.SOURCE + 'core_state.rs', 'clear_owned_region(&mut self.' + field + ')', 'Ok(())')
              for field in policy.REGIONS]
    cases += [(policy.CRATE + '/Cargo.toml', 'default = []', 'default = ["hardened-execution"]'),
              (policy.CRATE + '/src/lib.rs', '#[cfg(feature = "hardened-execution")]\npub mod execution;', 'pub mod execution;')]
    with tempfile.TemporaryDirectory(prefix='brynja-kmac-policy-') as directory:
        root = Path(directory)
        shutil.copytree(policy.ROOT / policy.CRATE, root / policy.CRATE, ignore=shutil.ignore_patterns('target'))
        policy.semantic(root)
        for name, before, after in cases:
            path = root / name
            original = path.read_text()
            policy.require(before in original, 'mutation target exists')
            try:
                path.write_text(original.replace(before, after))
                try:
                    policy.semantic(root)
                except ValueError:
                    continue
                raise ValueError('accepted semantic mutation: ' + before)
            finally:
                path.write_text(original)
    print(f'KMAC execution policy rejects {len(cases)} semantic regressions')


if __name__ == '__main__':
    main()
