#!/usr/bin/env python3
"""Compile deliberate AES defects in private copies; require named test failures."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hmac'))
import hmac_verifiers as verifier

ROOT = verifier.ROOT
KAT = ('--test', 'aes128', 'nist_aesavs_all_four_aes128_ecb_kat_files')
SCHEDULE = ('--lib', 'aes::tests::fips197_appendix_a1_complete_schedule')
PUBLIC_FAULT = ('--lib', 'aes::tests::public_encryption_failures_preserve_destination_and_clear_scratch')
MUTATIONS = (
    ('field-modulus', 'src/aes/portable/field.rs', '0x1b &', '0x1d &', KAT),
    ('forward-affine', 'src/aes/portable/field.rs', '^ 0x63', '^ 0x62', KAT),
    ('inverse-affine', 'src/aes/portable/field.rs', '^ 0x05', '^ 0x04', KAT),
    ('round-constant', 'src/aes/portable.rs', 'let mut rcon = 1;', 'let mut rcon = 2;', KAT),
    ('prior-key-word', 'src/aes/portable.rs', 'offset.wrapping_sub(16).wrapping_add(i)',
     'offset.wrapping_sub(12).wrapping_add(i)', KAT),
    ('shift-direction', 'src/aes/portable/layout.rs', 'column.wrapping_add(row) % 4',
     'column.wrapping_add(4).wrapping_sub(row) % 4', KAT),
    ('skip-round', 'src/aes/portable.rs', 'for round in 1..10 {', 'for round in 1..9 {', KAT),
    ('inverse-mix', 'src/aes/portable.rs', '*a = multiply(x, 14)', '*a = multiply(x, 15)', KAT),
    ('final-round-key', 'src/aes/portable.rs', '\n        add_key(state, schedule, 10)\n',
     '\n        add_key(state, schedule, 9)\n', KAT),
    ('skip-schedule-clear', 'src/aes.rs', 'let _ = clear_owned_region(&mut self.0);',
     'if N != 176 { let _ = clear_owned_region(&mut self.0); }', SCHEDULE),
    ('forget-key-clear', 'src/aes.rs',
     '/// Clears key storage immediately and consumes this owner.\n    pub fn clear(self) {\n        let _ = self.region.clear();\n    }',
     '/// Mutated test-only copy: forget instead of clear.\n    pub fn clear(self) {\n        core::mem::forget(self);\n    }', PUBLIC_FAULT),
    ('early-public-write', 'src/aes.rs',
     ') -> Result<(), Error> {\n        let mut schedule',
     ') -> Result<(), Error> {\n        output.copy_from_slice(input);\n        let mut schedule', PUBLIC_FAULT),
)
MARKER = 'AES mutations: PASS; 12 compiling defects rejected by named tests'
SCRATCH_MARKER = 'AES scratch: PASS; zero length rejected at compile time; positive control compiled'


def mutate(source, old, new):
    if source.count(old) != 1 or old == new:
        raise ValueError('mutation anchor must exist exactly once and change the source')
    return source.replace(old, new, 1)


def rejected(result, test):
    output = result.stdout + result.stderr
    return (result.returncode == 101 and 'running 1 test' in output
            and f'test {test} ... FAILED' in output
            and 'test result: FAILED. 0 passed; 1 failed; 0 ignored;' in output
            and 'assertion' in output)


def scratch_rejected(result):
    if result.returncode != 101:
        return False
    try:
        errors = [row['message'] for row in map(json.loads, result.stdout.splitlines())
                  if row.get('reason') == 'compiler-message' and row['message']['level'] == 'error']
        return (len(errors) == 1 and (errors[0].get('code') or {}).get('code') == 'E0080' and
                'AES scratch must not be empty' in errors[0]['message'] and
                any(s['is_primary'] and scratch_span(s) for s in errors[0]['spans']))
    except (ValueError, TypeError, AttributeError, KeyError):
        return False


def scratch_span(span):
    # rustc reports the panic macro body as primary; follow its call site,
    # never the macro definition site, back to the production constructor.
    while span:
        if span['file_name'] == 'src/aes.rs':
            return True
        span = (span.get('expansion') or {}).get('span')
    return False


def scratch_contract(directory, compiler):
    path = directory / 'src/aes.rs'
    original = path.read_text()
    env = verifier.environment(directory)
    env.update(CARGO_NET_OFFLINE='true', RUSTUP_AUTO_INSTALL='0')
    command = ['cargo', '+' + compiler, 'build', '--locked', '--offline', '--lib', '--message-format=json']
    try:
        path.write_text(original + '\npub fn scratch_probe() { let _ = Scratch::<1>::new(); }\n')
        verifier.run(command, env, directory)
        path.write_text(original + '\npub fn scratch_probe() { let _ = Scratch::<0>::new(); }\n')
        result = subprocess.run(command, cwd=directory, env=env, text=True, capture_output=True, timeout=120)
        if not scratch_rejected(result):
            raise ValueError('wrong empty-scratch failure: ' + result.stdout[-4000:] + result.stderr[-1000:])
    finally:
        path.write_text(original)
    verifier.run(command, env, directory)
    print(SCRATCH_MARKER, flush=True)


def prepare(directory):
    (directory / 'src').mkdir()
    # This isolated fixture exports only copied AES production code and uses
    # the actual core dependency. No changes are made to the source checkout.
    shutil.copy2(ROOT / 'crates/brynja-crypto/src/aes.rs', directory / 'src/aes.rs')
    shutil.copytree(ROOT / 'crates/brynja-crypto/src/aes', directory / 'src/aes')
    (directory / 'src/lib.rs').write_text('#![no_std]\n#![forbid(unsafe_code)]\npub mod aes;\n')
    (directory / 'tests').mkdir()
    shutil.copy2(ROOT / 'crates/brynja-crypto/tests/aes128.rs', directory / 'tests/aes128.rs')
    shutil.copytree(ROOT / 'crates/brynja-crypto/tests/fixtures/aes128', directory / 'tests/fixtures/aes128')
    # A quoted TOML literal path avoids shell interpolation and TOML escapes.
    core = ROOT / 'crates/brynja-core'
    if "'" in str(core) or '\n' in str(core):
        raise ValueError('unsupported fixture dependency path')
    (directory / 'Cargo.toml').write_text(
        '[workspace]\n[package]\nname="brynja-crypto"\nversion="0.0.0"\n'
        'edition="2024"\npublish=false\n[dependencies]\n'
        f"brynja-core={{path='{core}',default-features=false}}\n")


def campaign(directory, compiler):
    prepare(directory)
    env = verifier.environment(directory)
    env.update(CARGO_NET_OFFLINE='true', RUSTUP_AUTO_INSTALL='0')
    cargo = ['cargo', '+' + compiler]
    verifier.run([*cargo, 'generate-lockfile', '--offline'], env, directory)
    test = [*cargo, 'test', '--locked', '--offline']
    for selection, count in ((['--test', 'aes128'], 6), (['--lib', 'aes::'], 5)):
        output = verifier.run([*test, *selection], env, directory)
        if f'test result: ok. {count} passed; 0 failed; 0 ignored;' not in output:
            raise ValueError('unaltered AES baseline population failed')
    for name, relative, old, new, selection in MUTATIONS:
        path = directory / relative
        original = path.read_text()
        try:
            path.write_text(mutate(original, old, new))
            # Require successful compilation before considering an execution
            # failure. Compiler errors and missing fixtures are not kills.
            verifier.run([*test, *selection, '--no-run'], env, directory)
            result = subprocess.run([*test, *selection, '--', '--exact'], cwd=directory,
                                    env=env, text=True, capture_output=True, timeout=120)
            if not rejected(result, selection[-1]):
                raise ValueError(f'mutation survived or wrong failure: {name}\n{result.stdout[-2500:]}\n{result.stderr[-2500:]}')
            print('AES_MUTATION_REJECTED: ' + name, flush=True)
        finally:
            path.write_text(original)
    # Confirm restoration and unchanged baseline after the last defect.
    for selection, count in ((['--test', 'aes128'], 6), (['--lib', 'aes::'], 5)):
        output = verifier.run([*test, *selection], env, directory)
        if f'test result: ok. {count} passed; 0 failed; 0 ignored;' not in output:
            raise ValueError('restored AES baseline failed')
    print(MARKER, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    if len(MUTATIONS) != 12 or len({m[0] for m in MUTATIONS}) != 12:
        raise ValueError('mutation population drift')
    with verifier.cargo_environment.private_directory(ROOT) as temporary:
        campaign(Path(temporary), '1.99.1')
        scratch_contract(Path(temporary), '1.99.1')


if __name__ == '__main__':
    main()
