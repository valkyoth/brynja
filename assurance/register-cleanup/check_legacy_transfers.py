#!/usr/bin/env python3
"""Development borrowed legacy-engine regressions; not a release gate."""
from pathlib import Path
import argparse
import importlib.util
import shutil
import sys
import tempfile

from check import run
from check_callers import clean_environment

ROOT = Path(__file__).resolve().parents[2]


def isolated(root, family):
    source = ROOT / 'crates' / ('brynja-legacy-' + family)
    crate = root / family
    for name in ('src', 'tests'):
        shutil.copytree(source / name, crate / name)
    shutil.copyfile(source / 'README.md', crate / 'README.md')
    manifest = (source / 'Cargo.toml').read_text()
    for name, value in (('edition', '"2024"'), ('rust-version', '"1.90"'),
                        ('license', '"MIT OR Apache-2.0"'),
                        ('homepage', '"https://github.com/valkyoth/brynja"'),
                        ('repository', '"https://github.com/valkyoth/brynja"')):
        manifest = manifest.replace(name + '.workspace = true', name + ' = ' + value)
    manifest = manifest.replace('[lints]\nworkspace = true', '[workspace]')
    for name in ('brynja-core', 'brynja-hash-core'):
        manifest = manifest.replace(name + ' = { workspace = true',
                                    name + ' = { path = "' + str(ROOT / 'crates' / name) + '"')
    (crate / 'Cargo.toml').write_text(manifest)
    return crate


def campaign(crate, env, relative, custom=None):
    path = crate / relative
    original = path.read_text()
    # Omit each exact transfer independently. A compile error is not a pass.
    tail_name = 'last' if 'hardened_execution' in relative else 'byte'
    indentation = '        ' if 'hardened_execution' in relative else '                    '
    calls = (
        'brynja_core::copy_secret_region(destination, source)',
        'brynja_core::copy_secret_region(\n' + indentation +
        'core::slice::from_mut(destination),\n' + indentation +
        'core::slice::from_ref(' + tail_name + '),\n' + indentation[:-4] + ')',
        'brynja_core::copy_secret_region(&mut owner.output_staging, &owner.chaining_state)',
    )
    mutations = [(call, 'Ok::<(), brynja_core::SecretMemoryError>(())') for call in calls]
    mutations.append(('apply_secret_byte_mask(destination, 0xff, 0x80 >> valid)',
                      'apply_secret_byte_mask(destination, 0xff, 0x40 >> valid)'))
    if custom is not None:
        mutations = custom
    for before, _ in mutations:
        if original.count(before) != 1:
            raise ValueError('absent/ambiguous legacy transfer mutation: ' + before)
    for release in (False, True):
        command = ['cargo', '+1.98.1', 'test', '--locked', '--offline',
                   '--manifest-path', str(crate / 'Cargo.toml'), '--all-features']
        if release:
            command.append('--release')
        path.write_text(original)
        run(command, env)
        for before, after in mutations:
            try:
                path.write_text(original.replace(before, after))
                result = run(command, env, success=False)
                log = result.stdout + result.stderr
                if not result.returncode or 'test result: FAILED' not in log:
                    raise ValueError('legacy mutant must compile and fail: ' + before + '\n' + log[-3000:])
            finally:
                path.write_text(original)
        print(f'{crate.name}/{relative}: {len(mutations)} compiled transfer/padding mutants rejected; '
              f'release={release}: PASS', flush=True)


def batch_campaign(crate, env):
    campaign(crate, env, 'src/batch/owner.rs', [
        ('brynja_core::copy_secret_region(destination, &lane.output_staging)',
         'Ok::<(), brynja_core::SecretMemoryError>(())'),
        ('input.split_borrowed()', '(input.as_bytes(), None::<(&u8, u8)>)'),
    ])
    campaign(crate, env, 'src/batch/hardened_execution/mod.rs', [
        ('b.bit_len() >= 512', 'b.bit_len() >= 520'),
    ])
    campaign(crate, env, 'src/batch/hardened_execution/vector.rs', [
        ('b.bit_len() / 512', 'b.bit_len() / 1024'),
    ])


def main(native_md5_batch=False):
    with tempfile.TemporaryDirectory(prefix='brynja-legacy-transfers-') as temporary:
        root = Path(temporary)
        env = clean_environment()
        env['CARGO_TARGET_DIR'] = str(root / 'target')
        if native_md5_batch:
            # Validate every enumerated native CPU before requesting AVX2.
            sys.path.insert(0, str(ROOT / 'scripts/md5'))
            spec = importlib.util.spec_from_file_location(
                'md5_native_host', ROOT / 'scripts/md5/capture-md5-cpu-native.py')
            host = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(host)
            lane = 'amd-x86_64' if 'AuthenticAMD' in Path('/proc/cpuinfo').read_text() else 'intel-x86_64'
            _, features = host.host(lane)
            env.update(RUSTFLAGS='-C target-feature=' + features,
                       BRYNJA_REQUIRE_HARDENED_MD5='1')
        for family in (('md5',) if native_md5_batch else ('sha1', 'md5')):
            crate = isolated(root, family)
            run(['cargo', '+1.98.1', 'generate-lockfile', '--offline',
                 '--manifest-path', str(crate / 'Cargo.toml')], env)
            if native_md5_batch:
                batch_campaign(crate, env)
                continue
            campaign(crate, env, 'src/engine.rs')
            if family == 'sha1':
                campaign(crate, env, 'src/hardened_execution/engine.rs')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-md5-batch', action='store_true',
                        help='only MD5 batch mutants; requires validated native Linux AVX2')
    main(parser.parse_args().native_md5_batch)
