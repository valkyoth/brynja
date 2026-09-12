#!/usr/bin/env python3
"""Mutation checks for documentation status, installation and example coverage."""
import importlib.util
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('readmes', Path(__file__).with_name('check-crate-readmes.py'))
readmes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readmes)


def main():
    path = readmes.ROOT / 'crates/brynja-hash-sha2/README.md'
    original = path.read_text()
    before_use = original.index('## Use')
    first_table = original.index('## Cryptography Verification Status')
    status = original[first_table:before_use]
    mutants = [
        original.replace('# brynja-hash-sha2\n', '# wrong-crate\n'),
        original.replace('Security-first, first-party Rust', 'Incorrect shared header'),
        original.replace('Independently verified', 'Review omitted'),
        original.replace('Implemented |', 'Unknown |'),
        original.replace(status, '') + '\n' + status,
        original.replace('Hardware and SIMD', 'Unclassified dispatch'),
        original + '\nv0.24.38 introduced this feature.\n',
        original + '\n```toml\nbrynja = "0.20"\n```\n',
        original + '\n```toml\nbrynja-hash-sha2 = { version = "0.1" }\n```\n',
        original.replace('```rust', '```rust,no_run', 1),
        original.replace('```rust', '```rust,ignore', 1),
        original + '\n[Missing](https://github.com/valkyoth/brynja/blob/main/docs/absent-readme-test.md)\n',
    ]
    method = Path.read_text
    for changed in mutants:
        def text(subject, *args, **kwargs):
            return changed if subject == path else method(subject, *args, **kwargs)
        with patch.object(Path, 'read_text', text):
            try:
                readmes.validate()
            except ValueError:
                continue
        raise AssertionError('README regression escaped')
    # Missing wrapper/source coverage is independently exercised by the scope
    # tests; the baseline must keep both that validator and real rustdoc runs.
    commands = (readmes.ROOT / 'scripts/checks.sh').read_text().splitlines()
    for command in ('python3 scripts/repository/check-crate-readmes.py',
                    'python3 scripts/repository/test-crate-readmes.py',
                    'cargo test --locked --offline --manifest-path assurance/crate-readmes/Cargo.toml --doc'):
        assert commands.count(command) == 1
    print('Crate README policy rejects 12 header/status/timeline/pin/example/link regressions')


if __name__ == '__main__':
    main()
