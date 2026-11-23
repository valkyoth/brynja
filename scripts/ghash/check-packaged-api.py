"""Exercise the frozen portable GHASH consumer against verified local Cargo archives."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'assurance/ghash-public-api'
spec = importlib.util.spec_from_file_location('packaging', ROOT / 'scripts/hkdf/check-hkdf-public-api.py')
pkg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pkg)
ENDPOINTS = (pkg.MATRIX[0], pkg.MATRIX[-1])
FROZEN = {
    'tests/ghash_vectors/nist.rs': '4b6122bdce41b2eb0fdf36c9d070ec26a8db69e6dce64719b044e5676087274c',
    'tests/ghash_lifecycle.rs': '4f5e3b6a04937d3be4e718ccdd442f2f38a1cf25716cdad750f2c61540882625',
}


def check_graph(metadata, consumer, archives, versions, dependency, *, candidate=False, runtime=False):
    nodes = {n['id']: n for n in metadata['resolve']['nodes']}
    ids = {p['id']: p['name'] for p in metadata['packages']}
    edges = [(e['name'], ids[e['pkg']]) for e in nodes[metadata['resolve']['root']]['deps']]
    if edges != [('subject', dependency)]:
        raise ValueError('wrong consumer entry point')
    names = set()
    for p in metadata['packages']:
        name = p['name']
        if p['id'] == metadata['resolve']['root']:
            if name != 'ghash-consumer' or Path(p['manifest_path']) != consumer / 'Cargo.toml':
                raise ValueError('unexpected consumer root')
            continue
        if name not in versions or Path(p['manifest_path']).resolve() != (
                archives / f'{name}-{versions[name]}' / 'Cargo.toml'):
            raise ValueError('dependency outside reviewed archive graph')
        features = set(nodes[p['id']]['features'])
        expected = {'hazmat-ghash'}
        if candidate or runtime:
            expected.add('ghash-runtime-execution' if runtime else 'cpu')
            if name == 'brynja-crypto' and not any(
                    ids[e['pkg']] == 'brynja-crypto-cpu' for e in nodes[p['id']]['deps']):
                raise ValueError('missing candidate CPU dependency edge')
        if dependency == 'brynja' and name == 'brynja-crypto':
            if p['features'].get('default') != []:
                raise ValueError('facade inherited a nonempty crypto default')
            expected.add('default')
        if name in ('brynja', 'brynja-crypto') and features != expected:
            raise ValueError('unexpected GHASH opt-in feature set')
        if name not in ('brynja', 'brynja-crypto'):
            allowed = {'default', 'general-sha512-t'} if name == 'brynja-hash-sha2' else {'default'}
            if runtime and name == 'brynja-crypto-cpu':
                if 'ghash-runtime-execution' not in features:
                    raise ValueError('missing runtime kernel opt-in')
                allowed.add('ghash-runtime-execution')
            if features - allowed:
                raise ValueError('unexpected transitive feature')
        if ((name.endswith('-cpu') and not ((candidate or runtime) and name == 'brynja-crypto-cpu'))
                or name.endswith('-std') or name.startswith('brynja-legacy')):
            raise ValueError('unexpected portable dependency')
        names.add(name)
    if not {dependency, 'brynja-crypto', 'brynja-core'} <= names:
        raise ValueError('incomplete portable graph')
    if (candidate or runtime) and 'brynja-crypto-cpu' not in names:
        raise ValueError('missing candidate CPU dependency')


def prepare(root, dependency, versions):
    consumer = root / ('consumer-' + dependency)
    for path in ('README.md', 'src/lib.rs', 'tests/consumer.rs'):
        destination = consumer / path
        destination.parent.mkdir(exist_ok=True, parents=True)
        shutil.copyfile(FIXTURE / path, destination)
    archives = root / 'unpacked'
    patches = ''.join(f'{p}={{path={json.dumps(str(archives / (p+"-"+v)))}}}\n'
                      for p, v in versions.items())
    (consumer / 'Cargo.toml').write_text(
        '[workspace]\n[package]\nname="ghash-consumer"\nversion="0.0.0"\nedition="2024"\n'
        'rust-version="1.90"\npublish=false\n[lib]\nname="brynja_crypto"\n'
        '[features]\nraw=["subject/hazmat-ghash"]\n[dependencies]\n'
        f'subject={{package="{dependency}",version="={versions[dependency]}",'
        'default-features=false}\n[patch.crates-io]\n' + patches)
    # The archived integration tests import brynja_crypto::ghash. The shim
    # exports only the chosen dependency's public module under this spelling.
    route = 'crypto::' if dependency == 'brynja' else ''
    (consumer / 'src/route.rs').write_text(f'pub use subject::{route}ghash;\n')
    for path, digest in FROZEN.items():
        data = (archives / ('brynja-crypto-' + versions['brynja-crypto']) / path).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('frozen public test changed; review before replay')
        (consumer / 'tests' / Path(path).name).write_bytes(data)
    return consumer


def exact_suite(output, count):
    summaries = [line for line in output.splitlines() if line.startswith('test result:')]
    return len(summaries) == 1 and re.fullmatch(
        rf'test result: ok\. {count} passed; 0 failed; 0 ignored; 0 measured; '
        r'0 filtered out; finished in [0-9]+(?:\.[0-9]+)?s', summaries[0]) is not None


def check(consumer, compiler, dependency, versions, env):
    cargo = ['cargo', '+' + compiler]
    def run(*args):
        return pkg.run([*cargo, *args], consumer, env).stdout
    flags = ['--locked', '--offline', '--features', 'raw']
    metadata = json.loads(run('metadata', *flags, '--format-version', '1'))
    check_graph(metadata, consumer, consumer.parent / 'unpacked', versions, dependency)
    for profile in ([], ['--release']):
        for target, count in [('nist', 3), ('ghash_lifecycle', 4), ('consumer', 3)]:
            result = run('test', *flags, *profile, '--test', target)
            if not exact_suite(result, count):
                raise ValueError('incomplete packaged consumer suite: ' + target)
    if not exact_suite(run('test', *flags, '--doc'), 1):
        raise ValueError('README example did not pass')
    run('check', *flags, '--lib', '--target', 'thumbv7em-none-eabi')
    for extra in ([], ['--features', 'subject/default'], ['--features', 'subject/hazmat-aes-block']):
        cmd = cargo + ['check', '--lib', '--locked', '--offline', '--message-format=json', *extra]
        result = pkg.cargo_result(cmd, consumer, env, timeout=120)
        if not pkg.diagnostic_matches(result, 'E0432', filename='src/route.rs'):
            raise ValueError('packaged GHASH not isolated behind its opt-in')
    # Pair the alias rejection with a successful compile of the same program
    # using disjoint storage. A packaging or compiler setup failure cannot pass.
    source = consumer / 'src/bin/probe.rs'
    source.parent.mkdir(exist_ok=True)
    positive = ('use brynja_crypto::ghash::Ghash; fn main() { let mut w=[0;16]; let mut o=[0;16];'
                'let h=Ghash::new(&[0;16], &mut w, 0); let _r=h.finish(&mut o); }')
    cmd = ['check', *flags, '--bin', 'probe', '--message-format=json']
    try:
        pairs = [(positive, positive.replace('finish(&mut o)', 'finish(&mut w)'), 'E0499')]
        for owner in ('Ghash', 'SecretHash'):
            for bound in ('Send', 'Sync', 'Clone', 'Copy', 'core::fmt::Debug'):
                negative = (f'use brynja_crypto::ghash::{owner}; fn require<T:{bound}>() {{}} '
                            f"fn main() {{require::<{owner}<'static>>();}}")
                pairs.append((negative.replace('T:' + bound, 'T'), negative, 'E0277'))
        for valid, invalid, code in pairs:
            source.write_text(valid)
            run(*cmd)
            source.write_text(invalid)
            result = pkg.cargo_result(cargo + cmd, consumer, env, timeout=120)
            if not pkg.diagnostic_matches(result, code):
                raise ValueError('unexpected ownership diagnostic: ' + code)
    finally:
        source.unlink(missing_ok=True)
    # This separate host compatibility run deliberately enables every feature
    # of the dependency (not just features of the empty consumer manifest).
    features = next(p['features'] for p in metadata['packages'] if p['name'] == dependency)
    enabled = ','.join('subject/' + feature for feature in sorted(features))
    if not exact_suite(run('test', *flags, '--features', enabled, '--test', 'consumer'), 3):
        raise ValueError('all-feature host compatibility failed')
    print(f'{compiler} {dependency}: archives, vectors, lifecycle, differential, README, ownership, Cortex-M compile and all-feature host compatibility passed', flush=True)


def main():
    if any(k in os.environ for k in pkg.REJECT_ENV):
        raise ValueError('remove ambient toolchain, target or compiler overrides')
    with pkg.cargo_environment.private_directory(ROOT) as temporary:
        root = Path(temporary)
        env = pkg.isolated_env(root)
        versions = pkg.package_archives(root, pkg.MODERN, ENDPOINTS[-1], env)
        for dependency in ('brynja-crypto', 'brynja'):
            consumer = prepare(root, dependency, versions)
            pkg.run(['cargo', '+' + ENDPOINTS[0], 'generate-lockfile', '--offline'], consumer, env)
            for compiler in ENDPOINTS:
                check(consumer, compiler, dependency, versions, env)
    print('GHASH_PACKAGED_PORTABLE_COMPLETE')


if __name__ == '__main__':
    main()
