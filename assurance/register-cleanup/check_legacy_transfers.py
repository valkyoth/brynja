#!/usr/bin/env python3
"""Development borrowed legacy-engine regressions; not a release gate."""
from pathlib import Path
import shutil
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


def campaign(crate, env, relative):
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
        print(f'{crate.name}/{relative}: four compiled transfer/padding mutants rejected; '
              f'release={release}: PASS', flush=True)


def main():
    with tempfile.TemporaryDirectory(prefix='brynja-legacy-transfers-') as temporary:
        root = Path(temporary)
        env = clean_environment()
        env['CARGO_TARGET_DIR'] = str(root / 'target')
        for family in ('sha1', 'md5'):
            crate = isolated(root, family)
            run(['cargo', '+1.98.1', 'generate-lockfile', '--offline',
                 '--manifest-path', str(crate / 'Cargo.toml')], env)
            campaign(crate, env, 'src/engine.rs')
            if family == 'sha1':
                campaign(crate, env, 'src/hardened_execution/engine.rs')


if __name__ == '__main__':
    main()
