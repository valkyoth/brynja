#!/usr/bin/env python3
"""Positive-controlled compiler failures and actual modern dependency closures."""
import json
import subprocess
import tempfile
from pathlib import Path

import legacy_acceptance as policy


def graph():
    for features in ('--all-features', '--no-default-features'):
        raw = subprocess.check_output(['cargo', 'metadata', '--locked', '--offline',
                                      '--format-version', '1', features], cwd=policy.ROOT, timeout=60)
        data = json.loads(raw)
        names = {p['id']: p['name'] for p in data['packages']}
        nodes = {n['id']: n['dependencies'] for n in data['resolve']['nodes']}
        roots = {'brynja', 'brynja-core', 'brynja-crypto', 'brynja-pki', 'brynja-platform',
                 'brynja-tls', 'brynja-tls12', 'brynja-tls13', 'brynja-tls13-handshake',
                 'brynja-quic-tls', 'brynja-dtls', 'brynja-protocol'}
        if not roots <= set(names.values()):
            raise ValueError('modern graph inventory lost an owner')
        for node, name in names.items():
            if name not in roots:
                continue
            visited, pending = set(), [node]
            while pending:
                current = pending.pop()
                if current in visited:
                    continue
                visited.add(current)
                if names[current].startswith('brynja-legacy-'):
                    raise ValueError(f'legacy dependency entered {name}')
                pending.extend(nodes[current])


def compile_boundaries():
    with tempfile.TemporaryDirectory(prefix='brynja-legacy-isolation-') as temporary:
        root = Path(temporary)
        (root / 'src').mkdir()
        manifest = '[package]\nname="legacy-isolation-fixture"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\n'
        for name in ('brynja', 'brynja-legacy-sha1', 'brynja-legacy-md5'):
            path = (policy.ROOT / 'crates' / name).as_posix()
            manifest += f'{name} = {{ path={json.dumps(path)}, default-features=false }}\n'
        (root / 'Cargo.toml').write_text(manifest)
        (root / 'src/lib.rs').write_text('#![no_std]\n')
        subprocess.run(['cargo', 'generate-lockfile', '--offline'], cwd=root, check=True, timeout=60)
        def check(source):
            (root / 'src/lib.rs').write_text('#![no_std]\n' + source)
            return subprocess.run(['cargo', 'check', '--locked', '--offline', '--message-format=json'],
                                  cwd=root, capture_output=True, text=True, timeout=90)
        control = check('pub fn modern() { let _ = brynja::crypto::sha256(b"abc"); }\n'
                        'pub fn legacy() { let _ = brynja_legacy_sha1::sha1(b"abc"); let _ = brynja_legacy_md5::md5(b"abc"); }')
        if control.returncode:
            raise ValueError(f'positive compiler control failed: {control.stderr}')
        count = 0
        for family, state in (('sha1', 'HardenedSha1'), ('md5', 'HardenedMd5')):
            leaf = f'brynja_legacy_{family}::{state}'
            cases = [
                (f'pub fn bad() {{ let _ = brynja::crypto::{family}(b"abc"); }}', 'E0425'),
                (f'pub fn bad<T: brynja::crypto::HardenedSha2State>() {{}}\npub fn misuse() {{ bad::<{leaf}>(); }}', 'E0277'),
                (f'pub fn bad() {{ let _ = brynja::core::FipsServiceSet::builder().enable({leaf}::new()); }}', 'E0308'),
                (f'pub fn bad() {{ let _ = brynja::pki::{state}::new(); }}', 'E0433'),
                (f'pub fn bad() {{ let _ = brynja::crypto::{family}_sign(b"abc"); }}', 'E0425'),
                (f'pub fn bad() {{ let _ = brynja::crypto::{family}_password_hash(b"abc"); }}', 'E0425'),
                (f'pub fn bad() {{ let _ = brynja::tls::{state}::new(); }}', 'E0433'),
                (f'pub fn bad() {{ let s = {leaf}::new(); let _ = s.clone(); }}', 'E0599'),
            ]
            for source, expected in cases:
                result = check(source)
                diagnostics = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
                codes = {d['message']['code']['code'] for d in diagnostics
                         if d.get('reason') == 'compiler-message' and d['message'].get('code')}
                if result.returncode == 0 or expected not in codes:
                    raise ValueError(f'wrong compile-fail outcome: {family}: expected {expected}: {result.stdout}')
                count += 1
        print(f'Positive compiler control and {count} legacy non-admission cases: PASS')


if __name__ == '__main__':
    graph()
    compile_boundaries()
