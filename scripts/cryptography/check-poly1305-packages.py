"""Offline registry consumers: standalone Poly1305 (default) or RFC 8439 AEAD (--aead)."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import runpy
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('packages', ROOT / 'scripts/hkdf/check-hkdf-public-api.py')
pkg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pkg)
POLY = 'brynja-mac-poly1305'
AEAD = 'brynja-aead-chacha20poly1305'
CHACHA = 'brynja-cipher-chacha'


def aead_tests(consumer):
    tests = consumer / 'tests'
    tests.mkdir()
    support = ROOT / 'assurance/chacha20poly1305/src/public_api.rs'
    # A submodule, not a second integration-test target.
    (tests / 'support').mkdir()
    shutil.copyfile(support, tests / 'support/mod.rs')
    records = runpy.run_path(str(ROOT / 'scripts/cryptography/check-chacha20poly1305-vectors.py'))['records']()
    cases = ['mod support;']
    for i, (key, nonce, aad, plain, cipher, _, _, tag) in enumerate(records):
        args = ','.join(('' if pos == 1 else '&') + str(list(data))
                        for pos, data in enumerate([key, nonce, aad, plain, cipher, tag]))
        cases.append(f'#[test] fn rfc_{i}() {{ assert!(support::public_api({args}).is_some()); }}')
    (tests / 'vectors.rs').write_text('\n'.join(cases))
    return 2


def check_raw_imports(consumer, name, cargo, flags, env):
    # Use the identical probe as a positive control with the raw opt-in added.
    # A misspelled import or unrelated compiler failure cannot pass the pair.
    probe = consumer / 'src/bin/probe.rs'
    probe.parent.mkdir(exist_ok=True)
    namespace = 'subject::crypto' if name == 'brynja' else 'subject'
    try:
        for module, raw in [('poly1305', 'poly1305'), ('chacha20', 'hazmat-chacha20')]:
            probe.write_text(f'pub use {namespace}::{module};\nfn main() {{}}\n')
            cmd = cargo + ['check', '--bin', 'probe', '--locked', '--offline', *flags]
            result = pkg.cargo_result(cmd + ['--message-format=json'], consumer, env, timeout=120)
            if not pkg.diagnostic_matches(result, 'E0432'):
                raise ValueError(f'{name}: {module} should need its own façade opt-in')
            pkg.run(cmd + ['--features', 'subject/' + raw], consumer, env)
    finally:
        probe.unlink(missing_ok=True)


def check_route(root, registry, versions, hashes, name, env, leaf):
    aead = leaf == AEAD
    feature = 'chacha20poly1305' if aead else 'poly1305'
    module = {leaf: '', 'brynja-crypto': feature + '::', 'brynja': 'crypto::' + feature + '::'}[name]
    consumer = root / ('downstream-' + name)
    src = consumer / 'src'
    src.mkdir(parents=True)
    # The fixture's tests import this library; it only sees the *one*
    # selected registry dependency, not a path override or all façades together.
    (consumer / 'Cargo.toml').write_text(
        '[workspace]\n[package]\nname="poly-consumer"\nversion="0.0.0"\nedition="2024"\n'
        f'[lib]\nname="{leaf.replace("-", "_")}"\n'
        + (f'[features]\nopt-in=["subject/{feature}"]\n' if name != leaf else '')
        + '[dependencies]\n'
        f'subject={{package="{name}",version="={versions[name]}",default-features=false}}\n')
    (src / 'lib.rs').write_text(
        '#![no_std]\npub use subject::' + module +
        ('{Error, Opener, Sealer};\n' if aead else '{OneTimeKey, Error, Poly1305};\n'))
    if aead:
        expected_tests = aead_tests(consumer)
    else:
        shutil.copytree(root / 'unpacked' / f'{leaf}-{versions[leaf]}' / 'tests', consumer / 'tests')
        expected_tests = 4
    for compiler in (pkg.MATRIX[0], pkg.MATRIX[-1]):
        cargo = ['cargo', '+' + compiler, '--config', 'source.crates-io.replace-with="staged"',
                 '--config', 'source.staged.local-registry=' + json.dumps(str(registry))]
        if not (consumer / 'Cargo.lock').exists():
            pkg.run(cargo + ['generate-lockfile', '--offline'], consumer, env)
        base = ['--offline', '--locked']
        def graph(flags):
            info = json.loads(pkg.run(cargo + ['metadata', '--format-version', '1', *base, *flags],
                                      consumer, env).stdout)
            locked = {p['name']: p for p in tomllib.loads((consumer / 'Cargo.lock').read_text())['package']}
            names = set()
            for p in info['packages']:
                if p['id'] == info['resolve']['root']:
                    continue
                n = p['name']
                if (n not in hashes or not (p['source'] or '').startswith('registry+')
                        or p['version'] != versions[n] or locked[n].get('checksum') != hashes[n]):
                    raise ValueError(f'{name}: dependency not from the staged archive: {n}')
                names.add(n)
            if name not in names or 'brynja-crypto-cpu' in names or (not aead and CHACHA in names):
                raise ValueError(f'{name}: unexpected resolved graph')
            if aead and flags:
                for p in info['packages']:
                    if p['name'] in ('brynja', 'brynja-crypto'):
                        node = next(n for n in info['resolve']['nodes'] if n['id'] == p['id'])
                        if set(node['features']) - {'default', feature}:
                            raise ValueError(f'{name}: AEAD opted into unrelated façade features')
            return names
        flags = []
        if name != leaf:
            if {POLY, AEAD, CHACHA}.intersection(graph([])):
                raise ValueError(f'{name}: primitive or AEAD active without opt-in')
            result = pkg.cargo_result(cargo + ['check', '--lib', *base, '--message-format=json'],
                                      consumer, env, timeout=120)
            if not pkg.diagnostic_matches(result, 'E0432', filename='src/lib.rs'):
                raise ValueError(f'{name}: expected the disabled {feature} import to be unavailable')
            flags = ['--features', 'opt-in']
        names = graph(flags)
        required = {leaf, 'brynja-core'} | ({POLY, CHACHA} if aead else set())
        if not required <= names or (name == leaf and names != required) or (not aead and AEAD in names):
            raise ValueError(f'{name}: wrong {feature} graph')
        test = pkg.run(cargo + ['test', '--test', 'vectors', '--release', *base, *flags], consumer, env)
        if f'test result: ok. {expected_tests} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' not in test.stdout:
            raise ValueError(f'{name}: downstream RFC/lifecycle tests did not run')
        pkg.run(cargo + ['check', '--lib', '--target', 'thumbv7em-none-eabi', *base, *flags], consumer, env)
        if aead and name != leaf:
            check_raw_imports(consumer, name, cargo, flags, env)
        print(f'{compiler} {name}: registry archives, opt-in graph, host tests and Cortex-M build passed',
              flush=True)


def packaged_rvv(root, registry, versions, env, export):
    """Link just the staged crates on baseline RV64GC and export for native replay."""
    target = 'riscv64gc-unknown-linux-gnu'
    linker = shutil.which('riscv64-linux-gnu-gcc') or shutil.which('riscv64-suse-linux-gcc')
    if not linker:
        raise ValueError('RV64GC Linux cross-linker required')
    # Test the host's libc on hardware: the cross toolchain's static glibc
    # can enter its vector memcpy even when Linux disables V at exec.
    env = dict(env, CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER=linker)
    loader = 'ld-linux-riscv64-lp64d.so.1'
    libc_root = Path(subprocess.check_output([linker, '-print-sysroot'], text=True).strip())
    if not (libc_root / 'lib' / loader).is_file():
        libc_root = Path(subprocess.check_output([linker, '-print-file-name=' + loader],
                                                 text=True).strip()).parent.parent
    if not (libc_root / 'lib' / loader).is_file():
        raise ValueError('RV64 Linux GNU dynamic loader not found for QEMU')
    fixture = ROOT / 'assurance/poly1305'
    consumer = root / 'rvv-consumer'
    (consumer / 'src').mkdir(parents=True)
    (consumer / 'tests').mkdir()
    (consumer / 'Cargo.toml').write_text(
        '[workspace]\n[package]\nname="rvv-consumer"\nversion="0.0.0"\nedition="2024"\n'
        '[features]\nrvv=["brynja-mac-poly1305/poly1305-rvv"]\n[dependencies]\n'
        f'brynja-mac-poly1305={{version="={versions[POLY]}",default-features=false}}\n')
    vector_path = '../../../crates/brynja-mac-poly1305/tests/data/rfc8439.tsv'
    tests = (fixture / 'tests/rvv_vectors.rs').read_text()
    if tests.count(vector_path) != 1:
        raise ValueError('review the packaged vector input')
    (consumer / 'tests/vectors.rs').write_text(tests.replace(vector_path, 'rfc8439.tsv'))
    shutil.copyfile(root / 'unpacked' / f'{POLY}-{versions[POLY]}/tests/data/rfc8439.tsv',
                    consumer / 'tests/rfc8439.tsv')
    export.mkdir(exist_ok=False)
    for v in (pkg.MATRIX[0], pkg.MATRIX[-1]):
        cargo = ['cargo', '+' + v, '--config', 'source.crates-io.replace-with="staged"',
                 '--config', 'source.staged.local-registry=' + json.dumps(str(registry))]
        base = ['--release', '--locked', '--offline', '--target', target, '--message-format=json']
        pkg.run(cargo + ['generate-lockfile', '--offline'], consumer, env)
        (consumer / 'src/main.rs').write_text('pub use brynja_mac_poly1305::rvv::Rvv; fn main() {}\n')
        disabled = pkg.cargo_result(cargo + ['check', '--bin', 'rvv-consumer', *base],
                                    consumer, env, timeout=120)
        if not pkg.diagnostic_matches(disabled, 'E0432', filename='src/main.rs'):
            raise ValueError('default-off RVV import did not produce its expected diagnostic')
        pkg.run(cargo + ['check', '--bin', 'rvv-consumer', *base, '--features', 'rvv'], consumer, env)
        shutil.copyfile(fixture / 'examples/rvv_owner.rs', consumer / 'src/main.rs')
        for label, command, name in (
                ('owner', ['build', '--bin', 'rvv-consumer'], 'rvv-consumer'),
                ('vectors', ['test', '--no-run', '--test', 'vectors'], 'vectors')):
            result = pkg.run(cargo + command + [*base, '--features', 'rvv'], consumer, env)
            records = [json.loads(line) for line in result.stdout.splitlines()]
            exe, = [r['executable'] for r in records if r.get('reason') == 'compiler-artifact'
                    and r['target']['name'] == name and r.get('executable')]
            dst = export / f'{label}-{v}'
            shutil.copy2(exe, dst)
            if label == 'owner':
                denied = subprocess.run(['qemu-riscv64', '-L', libc_root, '-E',
                                         'LD_LIBRARY_PATH=/lib64:/lib64/lp64d:/lib', '-cpu', 'rv64,v=false', dst],
                                        capture_output=True, timeout=30)
                if (denied.returncode, denied.stdout, denied.stderr) != (2, b'', b'required RVV: Unavailable\n'):
                    raise ValueError('no-V packaged owner did not refuse cleanly')
            print(f'{dst.name}: {hashlib.sha256(dst.read_bytes()).hexdigest()}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--aead', action='store_true')
    group.add_argument('--rvv-export', type=Path, help='build packaged standalone RVV fixtures in a new directory')
    args = parser.parse_args()
    leaf = AEAD if args.aead else POLY
    with pkg.cargo_environment.private_directory(ROOT) as tmp:
        root = Path(tmp)
        env = pkg.isolated_env(root)
        packages = ('brynja-core', 'brynja-crypto-cpu', POLY) if args.rvv_export else pkg.MODERN
        versions = pkg.package_archives(root, packages, pkg.MATRIX[-1], env)
        registry = root / 'target/package/tmp-registry'
        if args.rvv_export:
            packaged_rvv(root, registry, versions, env, args.rvv_export.absolute())
            return
        hashes = {n: hashlib.sha256((root / 'target/package' / f'{n}-{v}.crate').read_bytes()).hexdigest()
                  for n, v in versions.items()}
        for name in (leaf, 'brynja-crypto', 'brynja'):
            check_route(root, registry, versions, hashes, name, env, leaf)


if __name__ == '__main__':
    main()
