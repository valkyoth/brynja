#!/usr/bin/env python3
"""Rehearse the public checkpoint using Cargo archives, never a registry upload."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import tomllib

from release_policy import ROOT, publish_plan, validate_repository


# (standalone package, feature, leaf item, compatibility item, facade forwarding)
ROUTES = (
    ('brynja-cipher-chacha', 'hazmat-chacha20', 'ChaCha20', 'chacha20::ChaCha20', False),
    ('brynja-cipher-aes', 'hazmat-aes-block', 'aes::Aes256Key', 'aes::Aes256Key', True),
    ('brynja-universal-hash-ghash', 'hazmat-ghash', 'ghash::Ghash', 'ghash::Ghash', True),
    ('brynja-aead-gcm', 'aes-gcm', 'aes_gcm::Aes256Gcm', 'aes_gcm::Aes256Gcm', True),
    ('brynja-aead-gcm', 'gmac', 'gmac::Aes256Gmac', 'gmac::Aes256Gmac', True),
)


def rehearsal(tmp, dirty):
    plan = validate_repository()
    selected = {n: plan['crates'][n]['version'] for n in publish_plan(plan)}
    build = tmp / 'build'
    subprocess.run(['cargo', '+1.100.0', 'package', '--quiet', '--locked', '--offline',
                    '--no-verify', '--target-dir', build, *(['--allow-dirty'] if dirty else []),
                    *(arg for n in selected for arg in ('-p', n))], cwd=ROOT, check=True)
    # Use Cargo's staged local registry (including its index), not unpacked path patches.
    registry = build / 'package/tmp-registry'
    digests = {}
    examples = {}
    for name, ver in selected.items():
        stem = f'{name}-{ver}'
        archive = registry / (stem + '.crate')
        digests[name] = hashlib.sha256(archive.read_bytes()).hexdigest()
        with tarfile.open(archive) as tar:
            for file in ('README.md', 'LICENSE-APACHE', 'LICENSE-MIT'):
                if tar.extractfile(f'{stem}/{file}').read() != (ROOT/'crates'/name/file).read_bytes():
                    raise ValueError(f'{stem}: archive does not match {file}')
            examples[name] = re.findall(r'^```rust\n(.*?)^```$', tar.extractfile(
                f'{stem}/README.md').read().decode(), re.M | re.S)
    consumer = tmp / 'consumer'
    (consumer/'src').mkdir(parents=True)
    dependencies = sorted({r[0] for r in ROUTES} | {'brynja-legacy-hkdf', 'brynja-crypto', 'brynja'})
    (consumer/'Cargo.toml').write_text('[workspace]\n[package]\nname="registry-smoke"\n'
        'version="0.0.0"\nedition="2024"\n[lints.cargo]\nunused_dependencies="allow"\n[dependencies]\n' + ''.join(
        f'{n}={{version="={selected[n]}",default-features=false}}\n' for n in dependencies))
    (consumer/'src/lib.rs').write_text('#![no_std]\n')
    for compiler in ('1.90.0', '1.100.0'):
        env = {**os.environ, 'CARGO_HOME': str(tmp/compiler/'cargo-home'),
               'CARGO_TARGET_DIR': str(tmp/compiler/'target')}
        cmd = ['cargo', '+' + compiler, '--config', 'source.crates-io.replace-with="checkpoint"',
               '--config', 'source.checkpoint.local-registry=' + json.dumps(str(registry))]

        def run(args, **kwargs):
            return subprocess.run(cmd + args, cwd=consumer, env=env, **kwargs)

        if not (consumer/'Cargo.lock').exists():
            run(['generate-lockfile', '--offline'], check=True)
        for p in tomllib.loads((consumer/'Cargo.lock').read_text())['package']:
            if p['name'] == 'registry-smoke':
                continue
            n = p['name']
            if (not p.get('source', '').startswith('registry+') or p['version'] != selected[n]
                    or p['checksum'] != digests[n]):
                raise ValueError(f'consumer did not resolve the selected registry archive: {n}')
        check = ['check', '--offline', '--locked', '--quiet']
        src = consumer/'src/lib.rs'
        for name, feature, leaf, compat, forwarded in ROUTES:
            leaf_path = name.replace('-', '_') + '::' + leaf
            module = leaf_path.rsplit('::', 1)[0]
            example, = (s for s in examples[name] if f'use {module}::' in s)
            src.write_text(f'#![no_std]\npub use {leaf_path} as Item;\n')
            rejected = run(check + ['--message-format=json'], capture_output=True, text=True)
            if rejected.returncode == 0 or not any(
                msg.get('reason') == 'compiler-message' and (msg['message'].get('code') or {}).get('code') == 'E0432'
                and any(span.get('is_primary') and span.get('file_name') == 'src/lib.rs'
                        for span in msg['message']['spans'])
                for msg in map(json.loads, rejected.stdout.splitlines())):
                raise ValueError(f'{compiler} {feature}: expected missing import with defaults off')
            imports = [(name, module), ('brynja-crypto', 'brynja_crypto::' + compat.rsplit('::', 1)[0])]
            if forwarded:
                imports.append(('brynja', 'brynja::crypto::' + compat.rsplit('::', 1)[0]))
            for owner, namespace in imports:
                # Enable just this route. Reuse the packaged public known answer,
                # changing only the import to exercise the compatibility route.
                (consumer/'src/main.rs').write_text(example.replace(f'use {module}::', f'use {namespace}::'))
                src.write_text(f'#![no_std]\npub use {namespace}::{compat.split("::")[-1]} as Item;\n')
                flags = ['--features', f'{owner}/{feature}']
                run(['run', '--locked', '--offline', '--quiet', *flags], check=True)
                run(check + ['--lib', '--target', 'thumbv7em-none-eabi', *flags], check=True)
                (consumer/'src/main.rs').unlink()
            params = "<'a,16>" if feature in ('aes-gcm', 'gmac') else "<'a>"
            source = (f'#![no_std]\npub fn via_crypto<\'a>(v:{leaf_path}{params})'
                      f' -> brynja_crypto::{compat}{params} {{ v }}\n')
            features = [f'{name}/{feature}', f'brynja-crypto/{feature}']
            if forwarded:
                source += (f'pub fn via_facade<\'a>(v:{leaf_path}{params})'
                           f' -> brynja::crypto::{compat}{params} {{ v }}\n')
                features.append(f'brynja/{feature}')
            src.write_text(source + 'pub use brynja_legacy_hkdf::Sha1Prk;\n')
            for target in ([], ['--target', 'thumbv7em-none-eabi']):
                run(check + ['--features', ','.join(features), *target], check=True)
        legacy, = examples['brynja-legacy-hkdf']
        src.write_text('#![no_std]\npub use brynja_legacy_hkdf::Sha1Prk;\n')
        (consumer/'src/main.rs').write_text(legacy)
        run(['run', '--locked', '--offline', '--quiet'], check=True)
        run(check + ['--lib', '--target', 'thumbv7em-none-eabi'], check=True)
        (consumer/'src/main.rs').unlink()
        print(f'{compiler}: registry-only known answers (14 cipher routes + legacy HKDF), type identity, default-off controls and Cortex-M compile passed')
    print(f'{len(selected)} candidate archives checked; no upload')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--working-tree', action='store_true', help='include uncommitted package edits for development')
    with tempfile.TemporaryDirectory(prefix='brynja-registry-rehearsal-') as tmp:
        rehearsal(Path(tmp), parser.parse_args().working_tree)
