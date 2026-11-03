#!/usr/bin/env python3
"""Run explicit packaged HKDF consumers; offline, no installs or publication."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/repository'))
import facade_cargo_environment as cargo_environment

MATRIX = ('1.90.0', '1.91.0', '1.92.0', '1.93.0', '1.94.0', '1.95.0',
          '1.96.0', '1.96.1', '1.97.0', '1.97.1', '1.98.0', '1.98.1', '1.99.0', '1.99.1')
MODERN = ('brynja', 'brynja-core', 'brynja-crypto', 'brynja-crypto-cpu',
          'brynja-crypto-cpu-std', 'brynja-dtls', 'brynja-hash-core',
          'brynja-hash-parallel', 'brynja-hash-sha2', 'brynja-hash-sha3',
          'brynja-hash-tuple', 'brynja-mac-hmac', 'brynja-mac-kmac', 'brynja-pki',
          'brynja-platform', 'brynja-protocol', 'brynja-quic-tls', 'brynja-tls',
          'brynja-tls12', 'brynja-tls13', 'brynja-tls13-handshake')
LEGACY = ('brynja-core', 'brynja-hash-core', 'brynja-legacy-hkdf',
          'brynja-legacy-hmac', 'brynja-legacy-md5', 'brynja-legacy-sha1')
FAMILIES = {'modern': ('hkdf-public-api', MODERN, 5),
            'legacy': ('legacy-hkdf-public-api', LEGACY, 4)}
REJECT_ENV = ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS',
              'RUSTC', 'RUSTDOC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
              'CARGO_BUILD_TARGET', 'RUSTUP_TOOLCHAIN')
PACKAGE_INPUTS = ('Cargo.toml', 'LICENSE-APACHE', 'LICENSE-MIT', 'README.md', 'src/**/*.rs')
GENERATED_FILES = {'Cargo.toml', 'Cargo.toml.orig', 'Cargo.lock', '.cargo_vcs_info.json'}


def isolated_env(root):
    # Do not inherit Cargo's open-ended configuration environment (including
    # target runners, wrappers and profile overrides), loader hooks or TMPDIR.
    # Installed tools and the rustup toolchain store are trusted local inputs.
    env = {key: os.environ[key] for key in ('PATH', 'HOME', 'RUSTUP_HOME')
           if key in os.environ}
    home = root / 'cargo-home'
    home.mkdir()
    env.update(CARGO_HOME=str(home), CARGO_TARGET_DIR=str(root / 'target'),
               RUSTUP_AUTO_INSTALL='0', CARGO_NET_OFFLINE='true',
               CARGO_TERM_COLOR='never', LC_ALL='C')
    return env


def run(command, cwd, env):
    cargo_environment.check(cwd, env)
    result = subprocess.run(command, cwd=cwd, env=env, text=True,
                            capture_output=True, timeout=300)
    if result.returncode:
        raise ValueError(f'command failed: {command}\n{result.stdout[-4000:]}\n{result.stderr[-4000:]}')
    return result


def unpack(archive, destination, prefix):
    total = 0
    seen = set()
    with tarfile.open(archive) as handle:
        for member in handle:
            path = Path(member.name)
            total += member.size
            if (path.is_absolute() or '..' in path.parts or not path.parts
                    or path.parts[0] != prefix or not member.isfile()
                    or path in seen or total > 32 * 1024 * 1024):
                raise ValueError('unexpected package archive entry')
            seen.add(path)
            stream = handle.extractfile(member)
            if stream is None:
                raise ValueError('missing package contents')
            target = destination / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(stream.read())


def diagnostic_matches(result, code):
    errors = []
    for line in result.stdout.splitlines():
        record = json.loads(line)
        if record.get('reason') != 'compiler-message':
            continue
        message = record['message']
        if message.get('level') == 'error':
            errors.append(message)
    codes = [code] if isinstance(code, str) else list(code)
    return (result.returncode != 0
            and [(error.get('code') or {}).get('code') for error in errors] == codes
            and all(any(span.get('is_primary') and span.get('file_name') == 'src/bin/probe.rs'
                        for span in error.get('spans', [])) for error in errors))


def ownership_probes(family):
    if family == 'modern':
        prefix = 'use brynja::crypto::hkdf::{Prk,DerivedKey,Sha256};\n'
        owners = ("Prk<'static,Sha256>", "DerivedKey<'static,Sha256>")
        create = 'Prk::<Sha256>::extract(None,b"ikm",&mut s)'
    else:
        prefix = 'use brynja_legacy_hkdf::{Sha1Prk,DerivedKey,LegacyUse};\n'
        owners = ("Sha1Prk<'static>", "DerivedKey<'static>")
        create = 'Sha1Prk::extract(LegacyUse::acknowledge(),None,b"ikm",&mut s)'
    cases = []
    for owner_name, owner in zip(('prk', 'output'), owners):
        for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
            negative = prefix + f'fn require<T: {bound}>() {{}} fn main() {{ require::<{owner}>(); }}'
            cases.append((f'{owner_name}-not-{bound}', negative,
                          negative.replace(f'T: {bound}', 'T'), 'E0277'))
    width = 32 if family == 'modern' else 20
    start = prefix + f'fn main() {{ let mut s=[0;{width}]; let p={create}.unwrap(); '
    for name, setup, owner in (('prk', '', 'p'),
                                ('output', 'let mut out=[0;32]; let k=p.expand(b"info",&mut out).unwrap(); ', 'k')):
        negative = start + setup + f'let _={owner}.clear(); let _={owner}.expose(); }}'
        positive = start + setup + f'let _={owner}.expose(); let _={owner}.clear(); }}'
        cases.append((f'{name}-use-after-clear', negative, positive, 'E0382'))
    negative = start + 'let k; { let mut out=[0;32]; k=p.expand(b"info",&mut out).unwrap(); } let _=k.expose(); }'
    positive = start + 'let mut out=[0;32]; let k=p.expand(b"info",&mut out).unwrap(); let _=k.expose(); }'
    cases.append(('output-outlives-buffer', negative, positive, 'E0597'))
    negative = start + 'let mut out=[0;32]; let parts=[&out[..1],&out[2..3]]; let k=p.expand_parts(&parts,&mut out).unwrap(); let _=k.expose(); }'
    positive = negative.replace('let parts=', 'let mut separate=[0;32]; let parts=').replace('&mut out).unwrap()', '&mut separate).unwrap()')
    cases.append(('multipart-overlap', negative, positive, 'E0502'))
    return cases


def probes(family):
    if family == 'modern':
        prefix = 'use brynja::crypto::hkdf::{Prk, Sha256, Sha384, Tls13Label};\n'
        cross = prefix + 'fn take(_: &Prk<Sha384>) {}\nfn main() { let mut s=[0;32]; let p=Prk::<Sha256>::extract(None,b"ikm",&mut s).unwrap(); take(&p); }'
        alias = prefix + 'fn main() { let mut s=[0;32]; let p=Prk::<Sha256>::extract(None,b"ikm",&mut s).unwrap(); let mut out=[0;32]; let label=Tls13Label::new(&out[..1],&[],32).unwrap(); let _key=p.expand_tls13(&label,&mut out).unwrap(); }'
        private = prefix + 'fn main() { let label=Tls13Label::new(b"key",&[],32).unwrap(); let mut out=[0;514]; let _=label.encode(&mut out); }'
        # Each negative has a nearby valid control, compiled on the same graph.
        return ownership_probes(family) + [
            # Both private Modern admission and the HMAC supertrait reject X.
            ('sealed', 'struct X; impl brynja::crypto::hkdf::Algorithm for X {} fn main() {}',
             'fn require<T: brynja::crypto::hkdf::Algorithm>() {} fn main() { require::<brynja::crypto::hkdf::Sha256>(); }',
             ('E0277', 'E0277')),
            ('cross-hash', cross, cross.replace('&Prk<Sha384>', '&Prk<Sha256>'), 'E0308'),
            ('overlap', alias, alias.replace('let label=', 'let mut separate=[0;32]; let label=').replace('&mut out).unwrap()', '&mut separate).unwrap()'), 'E0502'),
            ('private-encoder', private, private.replace('let _=label.encode(&mut out);', 'let _=(label.encoded_len(), &mut out);'), 'E0624'),
            ('implicit-legacy', 'use brynja::crypto::hkdf::Sha1; fn main() {}',
             'use brynja::crypto::hkdf::Sha256; fn main() {}', 'E0432'),
        ]
    negative = 'use brynja_legacy_hkdf::{Sha1Prk,LegacyUse}; fn main() { let mut s=[0;20]; let _=Sha1Prk::extract(None,b"ikm",&mut s); }'
    tls = 'use brynja_legacy_hkdf::{Sha1Prk,LegacyUse}; fn main() { let mut s=[0;20]; let p=Sha1Prk::extract(LegacyUse::acknowledge(),None,b"ikm",&mut s).unwrap(); let mut out=[0;20]; let _=p.expand_label(b"key",&[],&mut out); }'
    return ownership_probes(family) + [('acknowledgement', negative, negative.replace('::extract(None', '::extract(LegacyUse::acknowledge(),None'), 'E0061'),
            ('legacy-tls', tls, tls.replace('expand_label(b"key",&[],', 'expand(b"info",'), 'E0599')]


def public_negatives(family, consumer, cargo, env):
    source = consumer / 'src/bin/probe.rs'
    source.parent.mkdir(exist_ok=True)
    command = cargo + ['check', '--locked', '--offline', '--bin', 'probe', '--message-format=json']
    try:
        for name, negative, positive, code in probes(family):
            source.write_text(positive)
            run(command, consumer, env)
            source.write_text(negative)
            cargo_environment.check(consumer, env)
            result = subprocess.run(command, cwd=consumer, env=env, text=True,
                                    capture_output=True, timeout=120)
            if not diagnostic_matches(result, code):
                raise ValueError(f'{family}/{name} did not fail exclusively with {code}:\n{result.stdout[-4000:]}\n{result.stderr[-2000:]}')
    finally:
        source.unlink(missing_ok=True)


def packaged_graph(metadata, unpacked, family):
    packages = metadata['packages']
    required = {'hkdf-packaged-consumer', 'brynja-core',
                'brynja' if family == 'modern' else 'brynja-legacy-hkdf'}
    if not required <= {package['name'] for package in packages}:
        raise ValueError('consumer graph is incomplete')
    for package in packages:
        if package['name'] == 'hkdf-packaged-consumer':
            continue
        if not Path(package['manifest_path']).resolve().is_relative_to(unpacked):
            raise ValueError('consumer resolved a dependency outside packaged sources')
        if family == 'modern' and package['name'].startswith('brynja-legacy'):
            raise ValueError('modern consumer admitted a legacy dependency')


def package_files(crate):
    """Only the reviewed include forms; never approximate arbitrary Cargo globs."""
    for tree in (crate, crate / 'src', crate / 'tests'):
        if tree.is_symlink() or (tree != crate and tree.is_dir()
                                and any(p.is_symlink() for p in tree.rglob('*'))):
            raise ValueError('symlinked package input: ' + str(tree))
    if (crate / 'Cargo.toml').is_symlink():
        raise ValueError('symlinked package manifest')
    includes = tomllib.loads((crate / 'Cargo.toml').read_text())['package'].get('include')
    if includes not in (list(PACKAGE_INPUTS), [*PACKAGE_INPUTS, 'tests/**/*.rs']):
        raise ValueError('package requires a reviewed explicit include list: ' + str(crate))
    paths = set()
    for pattern in includes:
        for source in crate.glob(pattern):
            relative = source.relative_to(crate)
            if (not source.is_file() or any(p.is_symlink() for p in
                    (source, *source.parents) if p == crate or crate in p.parents)):
                raise ValueError('package input must be a regular non-symlink file: ' + str(source))
            paths.add(relative)
    if not {Path('Cargo.toml'), Path('src/lib.rs')} <= paths:
        raise ValueError('package is missing its manifest or library')
    return paths


def package_workspace(root, packages):
    # Resolve only this first-party closure. The full repository workspace has
    # unrelated registry dependencies; do not import its Cargo cache/config just
    # to package these crates. Preserve all inherited metadata/lints/profiles.
    source = (ROOT / 'Cargo.toml').read_text()
    if not source.startswith('[workspace]\n') or '[workspace.package]\n' not in source:
        raise ValueError('unexpected workspace manifest layout')
    inherited = source[source.index('[workspace.package]\n'):]
    workspace = root / 'package-workspace'
    for package in packages:
        crate = ROOT / 'crates' / package
        for relative in package_files(crate):
            target = workspace / 'crates' / package / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(crate / relative, target)
    members = json.dumps([f'crates/{package}' for package in packages])
    (workspace / 'Cargo.toml').write_text(
        f'[workspace]\nmembers={members}\nresolver="3"\n\n' + inherited)
    return workspace


def check_packaged_inputs(crate, unpacked):
    """Cargo-generated metadata may differ; selected source bytes may not."""
    expected = package_files(crate)
    actual = {p.relative_to(unpacked) for p in unpacked.rglob('*') if p.is_file()}
    generated = {Path(p) for p in GENERATED_FILES}
    if (actual - generated != expected - {Path('Cargo.toml')}
            or not {Path('Cargo.toml'), Path('Cargo.toml.orig')} <= actual):
        raise ValueError('archive file selection differs from declared package inputs')
    for relative in expected:
        archived = Path('Cargo.toml.orig') if relative == Path('Cargo.toml') else relative
        if (crate / relative).read_bytes() != (unpacked / archived).read_bytes():
            raise ValueError('archive input differs from source: ' + str(relative))


def check_family(family, toolchains, target, *, matrix=False):
    fixture, packages, count = FAMILIES[family]
    versions = {name: tomllib.loads((ROOT / 'crates' / name / 'Cargo.toml').read_text())['package']['version']
                for name in packages}
    with cargo_environment.private_directory(ROOT) as temporary:
        root = Path(temporary)
        env = isolated_env(root)
        workspace = package_workspace(root, packages)
        run(['cargo', '+' + toolchains[-1], 'generate-lockfile', '--offline'], workspace, env)
        command = ['cargo', '+' + toolchains[-1], 'package', '--locked', '--offline', '--allow-dirty', '--no-verify']
        for package in packages:
            command += ['-p', package]
        run(command, workspace, env)
        for package, version in versions.items():
            prefix = f'{package}-{version}'
            unpack(root / f'target/package/{prefix}.crate', root / 'unpacked', prefix)
            check_packaged_inputs(ROOT / 'crates' / package, root / 'unpacked' / prefix)
        consumer = root / 'consumers' / fixture
        shutil.copytree(ROOT / 'assurance' / fixture / 'src', consumer / 'src')
        shutil.copyfile(ROOT / 'assurance/hkdf-public-api-common.rs', root / 'consumers/hkdf-public-api-common.rs')
        # Normalized registry dependency plus patches to archives, never checkout paths.
        dependency = 'brynja' if family == 'modern' else 'brynja-legacy-hkdf'
        manifest = ('[workspace]\n[package]\nname="hkdf-packaged-consumer"\nversion="0.0.0"\n'
                    'edition="2024"\nrust-version="1.90"\npublish=false\n[dependencies]\n'
                    f'{dependency}={{version="={versions[dependency]}",default-features=false}}\n[patch.crates-io]\n')
        manifest += ''.join(f'{p}={{path="../../unpacked/{p}-{v}"}}\n' for p, v in versions.items())
        (consumer / 'Cargo.toml').write_text(manifest)
        run(['cargo', '+' + toolchains[0], 'generate-lockfile', '--offline'], consumer, env)
        for toolchain in toolchains:
            cargo = ['cargo', '+' + toolchain]
            metadata = json.loads(run(cargo + ['metadata', '--locked', '--offline', '--format-version', '1'], consumer, env).stdout)
            packaged_graph(metadata, root / 'unpacked', family)
            for profile in ([], ['--release']):
                result = run(cargo + ['test', '--locked', '--offline', '--lib', *profile], consumer, env)
                if f'test result: ok. {count} passed; 0 failed; 0 ignored;' not in result.stdout:
                    raise ValueError('consumer suite population changed')
            public_negatives(family, consumer, cargo, env)
            # Full host matrix; bare-metal compile at the supported endpoints.
            bare_metal = not matrix or toolchain in (MATRIX[0], MATRIX[-1])
            if bare_metal:
                run(cargo + ['check', '--locked', '--offline', '--lib', '--target', target], consumer, env)
            scope = f' and no_std {target}' if bare_metal else ' (host only)'
            print(f'HKDF packaged {family} {toolchain}: debug/release {count} tests, {len(probes(family))} diagnostic negatives{scope}: PASS', flush=True)
    if matrix:
        print(f'HKDF packaged public API {family}: MATRIX PASS; {len(MATRIX)} host compilers', flush=True)
    print(f'HKDF packaged public API {family}: PASS; no upload', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', choices=('modern', 'legacy', 'all'), default='all')
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--toolchain', action='append', help='Installed compiler; repeat for a matrix (default: 1.90.0 and 1.99.1)')
    selection.add_argument('--matrix', action='store_true', help='All 14 supported host compilers; bare-metal at 1.90.0 and 1.99.1')
    parser.add_argument('--target', default='thumbv7em-none-eabi')
    args = parser.parse_args()
    for name in REJECT_ENV:
        if name in os.environ:
            parser.error(f'remove ambient {name} before this check')
    toolchains = MATRIX if args.matrix else (args.toolchain or [MATRIX[0], MATRIX[-1]])
    for family in (FAMILIES if args.family == 'all' else [args.family]):
        check_family(family, toolchains, args.target, matrix=args.matrix)


if __name__ == '__main__':
    main()
