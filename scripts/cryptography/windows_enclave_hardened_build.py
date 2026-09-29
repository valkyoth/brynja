#!/usr/bin/env python3
"""Source-bound public-vector hardened-owner experiment; not a release gate."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

import windows_enclave_sha256_build as base

ROOT = base.ROOT
VARIANTS = {'normal': None, 'forgotten-output': 'probe_forget_output',
            'wrong-digest': 'probe_wrong_digest', 'missing-owner-clear': None}
FIELDS = [('chaining_state', 64), ('partial_input', 128), ('message_length', 16),
          ('phase', 2), ('message_schedule', 640), ('block_copy', 128),
          ('padding_block', 128), ('output_staging', 64)]


def layout_check(root=ROOT):
    """Permit raw initialized-byte inspection only for this exact field model."""
    folder = root / 'crates/brynja-hash-sha2/src/hardened'
    owner = (folder / 'owner.rs').read_text()
    body = re.search(r'pub\(crate\) struct HardenedSha2Owner\s*\{([^}]+)\}', owner)
    expected = ''.join(f'pub(crate){name}:[u8;{size}],' for name, size in FIELDS)
    if body is None or re.sub(r'\s', '', body[1]) != expected:
        raise ValueError('owner byte-layout changed; do not inspect opaque memory')
    scoped = (folder / 'in_place.rs').read_text()
    body = re.search(r'pub struct \$workspace\s*\{([^}]+)\}', scoped)
    expected = 'owner:HardenedSha2Owner,thread_bound:PhantomData<*mut()>,'.replace(' ', '')
    if body is None or re.sub(r'\s', '', body[1]) != expected:
        raise ValueError('workspace byte-layout changed; do not inspect opaque memory')
    if sum(size for _, size in FIELDS) != 1170:
        raise ValueError('workspace byte-count changed')


def build(directory, target, testing=False):
    base.check_graph()
    layout_check()
    if (ROOT / 'assurance/windows-enclave-probe/sha256_vectors.rs').read_text() != base.vector_source():
        raise ValueError('independent vectors changed')
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    commands = []
    mutations = {}
    def run(args):
        command = ['rustc', '+1.98.1', '--edition=2024', '-C', 'opt-level=2',
                   '-C', 'overflow-checks=yes', '-C', 'codegen-units=1',
                   '-C', 'force-unwind-tables=yes', '-C', 'embed-bitcode=yes',
                   '-C', 'panic=' + ('unwind' if testing else 'abort'), '--target', target, *args]
        commands.append(command)
        subprocess.run(command, cwd=ROOT, check=True, timeout=120)
    for variant, cfg in VARIANTS.items():
        libs = directory / (variant + '-libs')
        libs.mkdir(exist_ok=True)
        for crate in base.CRATES:
            source = ROOT / 'crates' / crate / 'src/lib.rs'
            if variant == 'missing-owner-clear' and crate == 'brynja-hash-sha2':
                mutated = libs / 'mutated-sha2-src'
                shutil.copytree(source.parent, mutated, dirs_exist_ok=True)
                owner = mutated / 'hardened/owner.rs'
                text = owner.read_text()
                token = 'pub(crate) fn wipe(&mut self) {'
                if text.count(token) != 1:
                    raise ValueError('exact owner cleanup mutation target missing')
                # Only the generated fixture copy changes; repository source is intact.
                owner.write_text(text.replace(token, token + '\n        return; // deliberate cleanup mutant'))
                mutations[variant] = {'source': 'crates/brynja-hash-sha2/src/hardened/owner.rs',
                                      'mutation': 'early return from wipe',
                                      'mutant_sha256': hashlib.sha256(owner.read_bytes()).hexdigest()}
                source = mutated / 'lib.rs'
            name = crate.replace('-', '_')
            args = ['--crate-type', 'rlib', '--crate-name', name, str(source),
                    '-o', str(libs / ('lib' + name + '.rlib'))]
            if crate == 'brynja-hash-sha2':
                args += ['-L', 'dependency=' + str(libs)]
                for dep in ('brynja_core', 'brynja_hash_core'):
                    args += ['--extern', dep + '=' + str(libs / ('lib' + dep + '.rlib'))]
                if variant == 'missing-owner-clear':
                    args += ['-A', 'unreachable_code']  # deliberate mutant only
            run(args)
        args = ['assurance/windows-enclave-probe/window_hardened.rs', '--crate-name', 'enclave_hardened',
                '-L', 'dependency=' + str(libs)]
        for dep in ('brynja_core', 'brynja_hash_sha2'):
            args += ['--extern', dep + '=' + str(libs / ('lib' + dep + '.rlib'))]
        if cfg:
            args += ['--cfg', cfg]
        if testing:
            suffix = '.exe' if 'windows' in target else ''
            run(args + ['--test', '-o', str(directory / (variant + suffix))])
        else:
            run(args + ['--crate-type', 'staticlib', '-C', 'lto=fat',
                        '--emit=' + ','.join(kind + '=' + str(directory / (variant + '_rust.' + suffix))
                                             for kind, suffix in [('link', 'lib'), ('asm', 's'), ('llvm-ir', 'll')])])
    return commands, mutations


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    commands, mutations = build(args.output, 'x86_64-pc-windows-msvc')
    identity = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True)
    (args.output / 'rustc-info.txt').write_text(identity)
    record = {'commands': commands, 'mutations': mutations, 'rustc': identity, 'features': [],
              'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in base.source_files()},
              'archives': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in args.output.glob('*_rust.lib')}}
    (args.output / 'rust-build.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Hardened-owner experiment archives built; not native or strict qualification')
