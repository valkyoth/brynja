#!/usr/bin/env python3
"""Repository policy for capability-focused, executable crate READMEs."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/zeroization'))
import scope_inputs


def validate(root=ROOT):
    paths = sorted((root / 'crates').glob('*/README.md'))
    expected = {path.parent / 'README.md' for path in (root / 'crates').glob('*/Cargo.toml')}
    if set(paths) != expected:
        raise ValueError('every crate must have one README')
    reference = (root / 'crates/brynja-hash-parallel/README.md').read_text().split('# brynja-hash-parallel\n', 1)[0]
    for path in paths:
        text = path.read_text()
        title = '# ' + path.parent.name + '\n'
        if text.count(title) != 1 or text.split(title, 1)[0] != reference:
            raise ValueError('crate README shared header/title changed: ' + str(path))
        body = text.split(title, 1)[1]
        headers = re.findall(r'^\|[^\n]+\|$', body, re.M)
        if not any('Implemented' in line and ('Independently verified' in line or 'Independent verification' in line)
                   for line in headers):
            # The facade intentionally uses family/crate mapping columns.
            if path.parent.name != 'brynja' or not any('Implementation status' in line and 'Independent verification' in line for line in headers):
                raise ValueError('missing implementation/independent table: ' + str(path))
        first_table = body.index('|')
        if '```' in body and first_table > body.index('```'):
            raise ValueError('capability table must precede examples: ' + str(path))
        if not ('Hardware' in body or 'SIMD' in body):
            raise ValueError('missing hardware/SIMD disposition: ' + str(path))
        if re.search(r'\bv0\.\d+(?:\.\d+)?\b', body):
            raise ValueError('release timeline in crate README: ' + str(path))
        if re.search(r'^brynja[\w-]*\s*=\s*(?:"\d|\{[^\n]*version\s*=)', body, re.M):
            raise ValueError('hard-coded dependency version in crate README: ' + str(path))
        if re.search(r'^```rust[^\n]*(?:ignore|no_run)', body, re.M):
            raise ValueError('README Rust examples must execute: ' + str(path))
        for url in re.findall(r'\]\(([^)]+)\)', text):
            for prefix in ('https://github.com/valkyoth/brynja/blob/main/',
                           'https://github.com/valkyoth/brynja/tree/main/'):
                if url.startswith(prefix) and not (root / url[len(prefix):].split('#', 1)[0]).exists():
                    raise ValueError('broken repository documentation link: ' + url)
    fixture = root / 'assurance/crate-readmes'
    scope_inputs.readme_fixture((fixture / 'Cargo.toml').read_bytes(), (fixture / 'Cargo.lock').read_bytes(),
                               (fixture / 'src/lib.rs').read_bytes(), (root / 'Cargo.lock').read_bytes())
    print(f'Crate README capability tables, links and executable inventory: PASS; crates={len(paths)}')


if __name__ == '__main__':
    validate()
