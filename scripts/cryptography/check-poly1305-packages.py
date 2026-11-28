"""Offline downstream Poly1305 checks against Cargo's staged registry, never an upload."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tomllib

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('packages', ROOT / 'scripts/hkdf/check-hkdf-public-api.py')
pkg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pkg)
LEAF = 'brynja-mac-poly1305'
ROUTES = {LEAF: '', 'brynja-crypto': 'poly1305::', 'brynja': 'crypto::poly1305::'}


def check_route(root, registry, versions, hashes, name, env):
    consumer = root / ('downstream-' + name)
    src = consumer / 'src'
    src.mkdir(parents=True)
    # The fixture's tests import this library; it only sees the *one*
    # selected registry dependency, not a path override or all façades together.
    (consumer / 'Cargo.toml').write_text(
        '[workspace]\n[package]\nname="poly-consumer"\nversion="0.0.0"\nedition="2024"\n'
        '[lib]\nname="brynja_mac_poly1305"\n'
        + ('[features]\nopt-in=["subject/poly1305"]\n' if name != LEAF else '')
        + '[dependencies]\n'
        f'subject={{package="{name}",version="={versions[name]}",default-features=false}}\n')
    (src / 'lib.rs').write_text(
        '#![no_std]\npub use subject::' + ROUTES[name] + '{OneTimeKey, Error, Poly1305};\n')
    shutil.copytree(root / 'unpacked' / f'{LEAF}-{versions[LEAF]}' / 'tests', consumer / 'tests')
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
            if name not in names or names.intersection({'brynja-cipher-chacha', 'brynja-crypto-cpu'}):
                raise ValueError(f'{name}: unexpected resolved graph')
            return names
        flags = []
        if name != LEAF:
            if LEAF in graph([]):
                raise ValueError(f'{name}: leaf active without opt-in')
            result = pkg.cargo_result(cargo + ['check', '--lib', *base, '--message-format=json'],
                                      consumer, env, timeout=120)
            if not pkg.diagnostic_matches(result, 'E0432', filename='src/lib.rs'):
                raise ValueError(f'{name}: expected the disabled Poly1305 import to be unavailable')
            flags = ['--features', 'opt-in']
        names = graph(flags)
        if LEAF not in names or (name == LEAF and names != {LEAF, 'brynja-core'}):
            raise ValueError(f'{name}: wrong Poly1305 graph')
        test = pkg.run(cargo + ['test', '--test', 'vectors', '--release', *base, *flags], consumer, env)
        if 'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' not in test.stdout:
            raise ValueError(f'{name}: packaged RFC/lifecycle tests did not run')
        pkg.run(cargo + ['check', '--lib', '--target', 'thumbv7em-none-eabi', *base, *flags], consumer, env)
        print(f'{compiler} {name}: registry archives, opt-in graph, host tests and Cortex-M build passed',
              flush=True)


def main():
    with pkg.cargo_environment.private_directory(ROOT) as tmp:
        root = Path(tmp)
        env = pkg.isolated_env(root)
        versions = pkg.package_archives(root, pkg.MODERN, pkg.MATRIX[-1], env)
        registry = root / 'target/package/tmp-registry'
        hashes = {n: hashlib.sha256((root / 'target/package' / f'{n}-{v}.crate').read_bytes()).hexdigest()
                  for n, v in versions.items()}
        for name in ROUTES:
            check_route(root, registry, versions, hashes, name, env)


if __name__ == '__main__':
    main()
