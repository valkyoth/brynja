#!/usr/bin/env python3
"""Compile and exchange all AES owner widths using only unpacked Cargo archives."""
from pathlib import Path
import importlib.util
import json
import os
import shutil

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('package_helpers', HERE.parent / 'hkdf/check-hkdf-public-api.py')
pkg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pkg)
ENDPOINTS = ('1.90.0', '1.100.0')
ROUTES = ('brynja-cipher-aes', 'brynja-crypto', 'brynja')


def visibility(cargo, fixture, env, flags):
    probe = fixture / 'src/bin/probe.rs'
    probe.parent.mkdir(exist_ok=True)
    cmd = cargo + ['check', '--bin', 'probe', '--message-format=json', *flags]
    for module in ('execution', 'provider'):
        probe.write_text(f'use brynja_cipher_aes::aes::{module} as _; fn main() {{}}')
        pkg.run(cmd + ['--features', 'leaf-only'], fixture, env)
        for route in ('brynja_crypto', 'brynja::crypto'):
            probe.write_text(f'use {route}::aes::{module} as _; fn main() {{}}')
            result = pkg.cargo_result(cmd + ['--features', 'leaf-only'], fixture, env, timeout=120)
            if not pkg.diagnostic_matches(result, 'E0432'):
                raise ValueError(f'unexpected compatibility visibility: {route}::{module}')
            pkg.run(cmd + ['--features', 'optional'], fixture, env)


def mode_visibility(cargo, fixture, env, versions):
    """Separate resolver: no dependency in this graph requests raw AES by default."""
    fixture.mkdir(exist_ok=True)
    probe = fixture / 'src/bin/probe.rs'
    probe.parent.mkdir(parents=True, exist_ok=True)
    manifest = '[workspace]\n[package]\nname="mode-probe"\nversion="0.0.0"\nedition="2024"\n[dependencies]\n'
    for route in (*ROUTES, 'brynja-universal-hash-ghash'):
        manifest += f'{route}={{version="={versions[route]}",default-features=false}}\n'
    manifest += '[patch.crates-io]\n' + ''.join(
        f'{name}={{path="../unpacked/{name}-{version}"}}\n' for name, version in versions.items())
    (fixture / 'Cargo.toml').write_text(manifest)
    probe.write_text('fn main() {}')
    pkg.run(cargo + ['generate-lockfile', '--offline'], fixture, env)

    def compile(source, features, code=None):
        probe.write_text(source)
        cmd = cargo + ['check', '--bin', 'probe', '--locked', '--offline', '--message-format=json',
                       '--features', ','.join(features)]
        if code is None:
            pkg.run(cmd, fixture, env)
        elif not pkg.diagnostic_matches(pkg.cargo_result(cmd, fixture, env, timeout=120), code):
            raise ValueError(f'unexpected mode opt-in result: {features} {source}')

    for route, prefix in [('brynja-crypto', 'brynja_crypto'), ('brynja', 'brynja::crypto')]:
        for mode, api in [('aes-gcm', 'aes_gcm::Aes128Gcm'), ('gmac', 'gmac::Aes128Gmac')]:
            for native in (False, True):
                flags = [route + '/' + mode + ('-execution' if native else '')]
                compile(f'use {prefix}::{api} as _; fn main() {{}}', flags)
                raw_hash = 'use brynja_universal_hash_ghash::ghash::Ghash as _; fn main() {}'
                compile(raw_hash, flags, 'E0603')
                # Cargo unifies the mode feature. The normal raw import stays
                # private, but Rust does not hide a public composition bridge.
                compile('use brynja_universal_hash_ghash::__mode::Ghash; '
                        'fn main() { let _ = Ghash::new; }', flags)
                compile(raw_hash, flags + ['brynja-universal-hash-ghash/hazmat-ghash'])
                raw = 'use brynja_cipher_aes::aes::Aes128Key as _; fn main() {}'
                compile(raw, flags, 'E0603')
                explicit = flags + ['brynja-cipher-aes/hazmat-aes-block']
                compile(raw, explicit)
                owner = 'use brynja_cipher_aes::aes::execution::Aes128Key as _; fn main() {}'
                compile(owner, explicit, 'E0603' if native else 'E0432')
                compile(owner, flags + ['brynja-cipher-aes/aes-static-execution'])
                bridge = 'brynja_cipher_aes::__mode::' + ('execution::' if native else '') + 'Aes128ExpandedKey'
                for method in ('decrypt_block', 'encrypt_block_public'):
                    compile(f'fn main() {{ let _ = {bridge}::{method}; }}', flags, 'E0599')

    compile(
        "use brynja_universal_hash_ghash::ghash as leaf; "
        "fn owner(x: leaf::Ghash<'_>) -> brynja_crypto::ghash::Ghash<'_> { x } "
        "fn output(x: brynja_crypto::ghash::SecretHash<'_>) -> brynja::crypto::ghash::SecretHash<'_> { x } "
        "fn error(x: brynja::crypto::ghash::Error) -> leaf::Error { x } fn main() {}",
        [route + '/hazmat-ghash' for route in ('brynja-universal-hash-ghash', 'brynja-crypto', 'brynja')])


def check():
    if any(key in os.environ for key in pkg.REJECT_ENV):
        raise ValueError('remove ambient compiler overrides')
    with pkg.cargo_environment.private_directory(pkg.ROOT) as temp:
        root = Path(temp)
        env = pkg.isolated_env(root)
        versions = pkg.package_archives(root, pkg.MODERN, ENDPOINTS[-1], env)
        fixture = root / 'consumer'
        fixture.mkdir()
        (fixture / 'src').mkdir()
        shutil.copyfile(pkg.ROOT / 'assurance/aes-leaf-identity/lib.rs', fixture / 'src/lib.rs')
        shutil.copyfile(pkg.ROOT / 'assurance/aes-leaf-identity/optional.rs', fixture / 'src/optional.rs')
        (fixture / 'src/main.rs').write_text(
            '#[cfg(feature="optional")] mod optional; fn main() { '
            '#[cfg(feature="optional")] optional::check(); identity::aes128().unwrap(); identity::aes192().unwrap(); '
            'identity::aes256().unwrap(); println!("AES_IDENTITY_OK"); }')
        manifest = ('[workspace]\n[package]\nname="identity"\nversion="0.0.0"\n'
                    'edition="2024"\npublish=false\n[features]\noptional=[' +
                    ','.join(f'"{route}/{feature}"' for route in ROUTES
                             for feature in ('aes-static-execution', 'external-key-provider')) +
                    ']\nleaf-only=["brynja-cipher-aes/aes-static-execution",'
                    '"brynja-cipher-aes/external-key-provider"]\n[dependencies]\n')
        for route in ROUTES:
            manifest += (f'{route}={{version="={versions[route]}",default-features=false,'
                         'features=["hazmat-aes-block"]}\n')
        manifest += '[patch.crates-io]\n'
        for name, version in versions.items():
            manifest += f'{name}={{path="../unpacked/{name}-{version}"}}\n'
        (fixture / 'Cargo.toml').write_text(manifest)
        for endpoint in ENDPOINTS:
            cargo = ['cargo', '+' + endpoint]
            pkg.run(cargo + ['generate-lockfile', '--offline'], fixture, env)
            flags = ['--offline', '--locked']
            metadata = json.loads(pkg.run(cargo + ['metadata', '--format-version=1', *flags], fixture, env).stdout)
            packages = {row['id']: row for row in metadata['packages']}
            active = [packages[node['id']] for node in metadata['resolve']['nodes']]
            for row in active:
                name = row['name']
                expected = (fixture if name == 'identity' else
                            root / 'unpacked' / f'{name}-{versions[name]}') / 'Cargo.toml'
                if Path(row['manifest_path']).resolve() != expected.resolve() or row['source'] is not None:
                    raise ValueError('consumer escaped packaged inputs: ' + name)
            names = [row['name'] for row in active]
            if any(names.count(name) != 1 for name in ROUTES) or 'brynja-crypto-cpu' in names:
                raise ValueError('unexpected raw portable dependency graph')
            run = pkg.run(cargo + ['run', '--bin', 'identity', '--release', '--quiet', *flags], fixture, env)
            if run.stdout.splitlines() != ['AES_IDENTITY_OK']:
                raise ValueError('missing completion for all three widths')
            pkg.run(cargo + ['check', '--lib', '--target', 'thumbv7em-none-eabi', *flags], fixture, env)
            optional = pkg.run(cargo + ['run', '--bin', 'identity', '--release', '--quiet', '--features', 'optional', *flags], fixture, env)
            if optional.stdout.splitlines() != ['AES_IDENTITY_OK']:
                raise ValueError('missing provider and unavailable-backend checks')
            visibility(cargo, fixture, env, flags)
            mode_visibility(cargo, root / 'mode-probe', env, versions)
            print(endpoint + ': GCM and GMAC do not opt a featureless leaf into raw or static AES', flush=True)
            print(endpoint + ': three packaged widths and import routes; Cortex-M compile passed', flush=True)
            print(endpoint + ': all provider widths quarantined short writes; unavailable kernel rejected', flush=True)


if __name__ == '__main__':
    check()
