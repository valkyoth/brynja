#!/usr/bin/env python3
"""Check named guide selection against prepended code blocks and section drift."""
from pathlib import Path
from strict_facade_package import section_example

ROOT = Path(__file__).resolve().parents[2]
guide = (ROOT/'docs/windows-enclave-sha3.md').read_text()
heading = 'Stream and retain output'
expected = section_example(guide, heading)
assert 'fn public_example(' in expected
assert 'Session::open(image, policy)' in expected
assert 'open_avx2' not in expected
for prefix in ('```rust,no_run\ninvalid Rust\n```\n',
               '## Another API\n```rust,no_run\n# hidden rustdoc line\n```\n'):
    assert section_example(prefix + guide, heading) == expected
for mutant in (guide.replace('## '+heading, '## Renamed section'),
               guide + '\n## '+heading+'\n',
               guide.replace('fn public_example', '```\n```rust,no_run\nfn public_example'),
               guide.replace('```rust,no_run', '```text')):
    try:
        section_example(mutant, heading)
    except ValueError:
        pass
    else:
        raise AssertionError('guide-selection mutation survived')
print('Named facade guide example: two insertion passes, four malformed-section rejections')
