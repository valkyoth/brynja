#!/usr/bin/env python3
"""Bounded emitted public AES owner Drop dispatch, not whole-frame erasure."""
import argparse
from pathlib import Path
import re
import sys
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hkdf'))
import hkdf_owner_codegen as dispatch
import hmac_verifiers as verifier

ROOT = verifier.ROOT
FIXTURE = ROOT / 'assurance/aes-owner-cleanup'
CRATE = 'brynja_aes_owner_cleanup'
PROBES = {'key_drop': 'Aes128Key', 'block_drop': 'SecretBlock', 'expanded_drop': 'Aes128ExpandedKey',
          'aes192_key_drop': 'Aes192Key', 'aes192_expanded_drop': 'Aes192ExpandedKey',
          'aes256_key_drop': 'Aes256Key', 'aes256_expanded_drop': 'Aes256ExpandedKey'}
MARKER = 'AES owner dispatch complete: 4 configurations; delegated core Drop; not scratch, physical-erasure or timing qualification'


def require(condition, message):
    if not condition:
        raise ValueError('AES owner dispatch: ' + message)


def policy():
    manifest = tomllib.loads((FIXTURE / 'Cargo.toml').read_text())
    require(manifest == {
        'package': {'name': 'brynja-aes-owner-cleanup', 'version': '0.0.0',
                    'edition': '2024', 'rust-version': '1.90', 'publish': False},
        'workspace': {},
        'dependencies': {'brynja-crypto': {'path': '../../crates/brynja-crypto', 'default-features': False,
                                          'features': ['hazmat-aes-block']}},
        'profile': {'release': {'opt-level': 3, 'lto': 'fat', 'codegen-units': 1, 'overflow-checks': True}},
    }, 'fixture build policy changed')


def check(llvm, panic):
    require(panic in ('abort', 'unwind'), 'unsupported panic mode')
    require('target triple = "x86_64-unknown-linux-gnu"' in llvm, 'wrong target layout')
    definitions, aliases = dispatch.definitions_and_aliases(llvm)
    selected = {}
    for probe in PROBES:
        suffix = str(len(CRATE)) + CRATE + str(len(probe)) + probe
        names = [name for name in (*definitions, *aliases)
                 if re.search(suffix + r'(?:17h[0-9a-f]+E)?$', name)]
        require(len(names) == 1, 'missing or ambiguous probe: ' + probe)
        selected[probe] = dispatch.resolve(names[0], definitions, aliases)
    for arguments, body in selected.values():
        require(('landingpad ' in body) == (panic == 'unwind'), 'panic profile mismatch')
        for populated in (False, True):
            for observer_unwinds in ((False, True) if panic == 'unwind' else (False,)):
                # All seven AES owners contain precisely one OwnedSecretRegion:
                # the same two-word descriptor ABI as the executor's "prk"
                # case. No HKDF algorithm or output-option premise is used.
                dispatch.execute(arguments, body, 'prk', True, populated,
                                 panic == 'unwind', observer_unwinds)
    return len(selected)


def negative_controls(llvm, panic):
    mutants = {
        'wrong-destructor': llvm.replace('OwnedSecretRegion', 'OtherSecretRegion'),
        'missing-observer': llvm.replace('%observer(', '%missing('),
        'wrong-pointer': re.sub(r'store ptr %0,', 'store ptr null,', llvm),
        'short-range': re.sub(r'store i64 %1,', 'store i64 0,', llvm),
        'missing-drop': re.sub(r'(?:tail )?call void @[^\n]*OwnedSecretRegion[^\n]*\n', '', llvm),
        'early-return': llvm.replace('start:\n', 'start:\n  ret void\n'),
        'post-drop-write': llvm.replace('  ret void', '  store ptr null, ptr %owner, align 8\n  ret void'),
        'unknown-instruction': llvm.replace('start:\n', 'start:\n  fence seq_cst\n'),
        'wrong-target': llvm.replace('target triple = "x86_64-unknown-linux-gnu"', 'target triple = "aarch64-unknown-linux-gnu"'),
        'missing-probe': llvm.replace('key_drop', 'missing_key'),
        'uninitialized-length': re.sub(r'  store i64 %1,[^\n]*\n', '', llvm),
        'repeated-observer': llvm.replace('  ret void', '  call void %observer(ptr %owner)\n  ret void'),
    }
    for name, mutant in mutants.items():
        require(mutant != llvm, 'vacuous negative control: ' + name)
        try:
            check(mutant, panic)
        except ValueError:
            continue
        raise ValueError('accepted emitted-IR negative control: ' + name)
    return len(mutants)


def collect(directory, compiler, panic):
    env = verifier.environment(directory)
    env.update(CARGO_PROFILE_RELEASE_PANIC=panic, CARGO_NET_OFFLINE='true', RUSTUP_AUTO_INSTALL='0')
    verifier.run(['cargo', '+' + compiler, 'rustc', '--manifest-path', str(FIXTURE / 'Cargo.toml'),
                  '--locked', '--offline', '--release', '--lib', '--target', 'x86_64-unknown-linux-gnu',
                  '--', '--emit=mir,llvm-ir,asm'], env)
    artifacts = {}
    for extension in ('mir', 'll', 's'):
        paths = list((directory / 'target/x86_64-unknown-linux-gnu/release/deps').glob(CRATE + '-*.' + extension))
        require(len(paths) == 1, 'missing or ambiguous emitted artifact')
        artifacts[extension] = paths[0].read_text()
    for name, owner in PROBES.items():
        require(re.search(r'^fn ' + name + r"\(_1: " + owner + r"<'_", artifacts['mir'], re.M),
                'actual owner MIR identity absent: ' + name)
        require(name in artifacts['s'], 'assembly probe absent: ' + name)
    require('OwnedSecretRegion' in artifacts['s'], 'assembly destructor absent')
    count = check(artifacts['ll'], panic)
    negative = negative_controls(artifacts['ll'], panic)
    print(f'AES owner dispatch: PASS; Rust {compiler}; x86_64; panic={panic}; '
          f'{count} probes; {negative} rejected IR mutations', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    policy()
    for compiler in ('1.90.0', '1.99.1'):
        for panic in ('abort', 'unwind'):
            with verifier.cargo_environment.private_directory(ROOT) as temporary:
                collect(Path(temporary), compiler, panic)
    print(MARKER)


if __name__ == '__main__':
    main()
