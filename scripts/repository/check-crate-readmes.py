#!/usr/bin/env python3
"""Repository policy for capability-focused, executable crate READMEs."""
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/zeroization'))
import scope_inputs

IMAGE = 'https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp'


def header(reference, name, published):
    """Shared branding, but navigation belongs to this package, not the facade."""
    if published:
        return reference.replace('https://crates.io/crates/brynja"', f'https://crates.io/crates/{name}"').replace(
            'https://docs.rs/brynja"', f'https://docs.rs/{name}"')
    return reference.replace('<a href="https://crates.io/crates/brynja">Crates.io</a>',
        f'<a href="https://github.com/valkyoth/brynja/tree/main/crates/{name}">Source (unpublished)</a>').replace(
        '<a href="https://docs.rs/brynja">Docs.rs</a>',
        f'<a href="https://github.com/valkyoth/brynja/blob/main/crates/{name}/src/lib.rs">API source</a>')


def validate(root=ROOT):
    paths = sorted((root / 'crates').glob('*/README.md'))
    expected = {path.parent / 'README.md' for path in (root / 'crates').glob('*/Cargo.toml')}
    if set(paths) != expected:
        raise ValueError('every crate must have one README')
    reference = (root / 'README.md').read_text().split('# brynja\n', 1)[0]
    if (reference.count(f'src="{IMAGE}"') != 1 or '<img width="840"' not in reference
            or not re.search(r'<img [^>]*alt="[^"]+"', reference)):
        raise ValueError('shared README image must be the remotely rendered project image')
    image = (root / '.github/images/brynja.webp').read_bytes()
    if not (image[:4] == b'RIFF' and image[8:12] == b'WEBP'):
        raise ValueError('shared README image is missing or not WebP')
    for path in paths:
        text = path.read_text()
        manifest = tomllib.loads(path.with_name('Cargo.toml').read_text())
        if manifest['package']['name'] != path.parent.name or manifest['package'].get('readme', 'README.md') != 'README.md':
            raise ValueError('crate README must match package metadata: ' + str(path))
        title = '# ' + path.parent.name + '\n'
        expected_header = header(reference, path.parent.name, manifest['package'].get('publish') is not False)
        if text.count(title) != 1 or text.split(title, 1)[0] != expected_header:
            raise ValueError('crate README shared header/title changed: ' + str(path))
        body = text.split(title, 1)[1]
        if '```rust\n' not in body and not re.search(
                r'```sh\n[^`]*\bcargo (?:test|check) --locked -p ' + re.escape(path.parent.name) + r'\b', body):
            raise ValueError('crate README needs an executable example or honest boundary check: ' + str(path))
        headers = re.findall(r'^\|[^\n]+\|$', body, re.M)
        if not any('Implemented' in line and ('Independently verified' in line or 'Independent verification' in line)
                   for line in headers):
            # The facade intentionally uses family/crate mapping columns.
            if path.parent.name != 'brynja' or not any('Implementation status' in line and 'Independent verification' in line for line in headers):
                raise ValueError('missing implementation/independent table: ' + str(path))
        first_table = body.index('|')
        if '```' in body and first_table > body.index('```'):
            raise ValueError('capability table must precede examples: ' + str(path))
        if not re.search(r'^##[^\n]*\b(?:Hardware|SIMD)\b', body, re.M):
            raise ValueError('missing hardware/SIMD disposition: ' + str(path))
        if re.search(r'\bv0\.\d+(?:\.\d+)?\b', body):
            raise ValueError('release timeline in crate README: ' + str(path))
        if re.search(r'^brynja[\w-]*\s*=\s*(?:"\d|\{[^\n]*version\s*=)', body, re.M):
            raise ValueError('hard-coded dependency version in crate README: ' + str(path))
        if re.search(r'^```rust[^\n]*(?:ignore|no_run)', body, re.M):
            raise ValueError('README Rust examples must execute: ' + str(path))
        for url in re.findall(r'\]\(([^)]+)\)', text):
            if not url.startswith(('https://', 'http://', '#')):
                raise ValueError('crate README link requires repository-independent URL: ' + url)
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
