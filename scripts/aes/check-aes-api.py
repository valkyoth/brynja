#!/usr/bin/env python3
"""Diagnostic-specific AES ownership checks against checkout-built public APIs."""
import argparse
import json
import re
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hmac'))
import hmac_verifiers as verifier

TOOLCHAINS = ('1.90.0', '1.99.1')
PREFIX = 'use brynja_crypto::aes::{Aes128Key,SecretBlock,PublicCiphertext};\n'
START = PREFIX + 'fn main() { let mut s=[0;16]; let key=Aes128Key::new(&[0;16],&mut s).unwrap(); '
BLOCK = 'let mut out=[0;16]; let block=key.encrypt_block(&[0;16],&mut out).unwrap(); '


def probes():
    cases = []
    for name, owner in (('key', "Aes128Key<'static>"), ('output', "SecretBlock<'static>")):
        for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
            negative = PREFIX + f'fn require<T: {bound}>() {{}} fn main() {{ require::<{owner}>(); }}'
            cases.append((name + '-not-' + bound, negative,
                          negative.replace(f'T: {bound}', 'T'), 'E0277'))
    use_key = 'let _=key.encrypt_block(&[0;16],&mut [0;16]); '
    cases += [
        ('key-use-after-clear', START + 'key.clear(); ' + use_key + '}',
         START + use_key + 'key.clear(); }', 'E0382'),
        ('output-use-after-clear', START + BLOCK + 'block.clear(); let _=block.expose(); }',
         START + BLOCK + 'let _=block.expose(); block.clear(); }', 'E0382'),
    ]
    for name, key_width, storage_width in (('aes192-rejected', 24, 16),
                                          ('aes256-rejected', 32, 16),
                                          ('short-key-storage', 16, 15)):
        negative = PREFIX + f'fn main() {{ let _=Aes128Key::new(&[0;{key_width}],&mut [0;{storage_width}]); }}'
        positive = PREFIX + 'fn main() { let _=Aes128Key::new(&[0;16],&mut [0;16]); }'
        cases.append((name, negative, positive, 'E0308'))
    for name, input_width, output_width in (('short-block', 15, 16), ('short-output', 16, 15)):
        cases.append((name, START + f'let _=key.encrypt_block(&[0;{input_width}],&mut [0;{output_width}]); }}',
                      START + use_key + '}', 'E0308'))
    for method in ('encrypt_block', 'decrypt_block', 'encrypt_block_public'):
        authority = ',PublicCiphertext::acknowledge()' if method.endswith('_public') else ''
        call = f'let _=key.{method}(&out,&mut out{authority}); }}'
        negative = START + 'let mut out=[0;16]; ' + call
        positive = negative.replace('&out,&mut out', '&[0;16],&mut out')
        cases.append((method + '-overlap', negative, positive, 'E0502'))
    cases += [
        ('live-key-storage', START + 's.fill(1); ' + use_key + '}',
         START + use_key + 'key.clear(); s.fill(1); }', 'E0499'),
        ('live-output-storage', START + BLOCK + 'out.fill(1); let _=block.expose(); }',
         START + BLOCK + 'block.clear(); out.fill(1); }', 'E0499'),
        ('output-outlives-buffer', START + 'let block; { let mut out=[0;16]; block=key.encrypt_block(&[0;16],&mut out).unwrap(); } let _=block.expose(); }',
         START + BLOCK + 'let _=block.expose(); }', 'E0597'),
        ('key-outlives-storage', PREFIX + 'fn main() { let key; { let mut s=[0;16]; key=Aes128Key::new(&[0;16],&mut s).unwrap(); } ' + use_key + '}',
         START + use_key + '}', 'E0597'),
        ('no-key-export', START + 'let _=key.expose(); }', START + use_key + '}', 'E0599'),
        ('public-acknowledgement', START + 'let _=key.encrypt_block_public(&[0;16],&mut [0;16]); }',
         START + 'let _=key.encrypt_block_public(&[0;16],&mut [0;16],PublicCiphertext::acknowledge()); }', 'E0061'),
        ('private-acknowledgement-field', PREFIX + 'fn main() { let _=PublicCiphertext { _private: () }; }',
         PREFIX + 'fn main() { let _=PublicCiphertext::acknowledge(); }', 'E0451'),
        ('no-public-decryption', START + 'let _=key.decrypt_block_public(&[0;16],&mut [0;16],PublicCiphertext::acknowledge()); }',
         START + 'let _=key.decrypt_block(&[0;16],&mut [0;16]); }', 'E0599'),
        ('consumed-acknowledgement', START + 'let authority=PublicCiphertext::acknowledge(); let _=key.encrypt_block_public(&[0;16],&mut [0;16],authority); let _=key.encrypt_block_public(&[0;16],&mut [0;16],authority); }',
         START + 'let _=key.encrypt_block_public(&[0;16],&mut [0;16],PublicCiphertext::acknowledge()); let _=key.encrypt_block_public(&[0;16],&mut [0;16],PublicCiphertext::acknowledge()); }', 'E0382'),
    ]
    def cached(source):
        source = source.replace('Aes128Key', 'Aes128ExpandedKey').replace('s=[0;16]', 's=[0;176]')
        return re.sub(r'(Aes128ExpandedKey::new\(&\[0;\d+\],&mut\s*\[0;)(16|15)(\]\))',
                      lambda m: m[1] + ('176' if m[2] == '16' else '175') + m[3], source)
    cases += [('cached-' + name, cached(negative), cached(positive), code)
              for name, negative, positive, code in list(cases)]
    if len(cases) != 58 or len({c[0] for c in cases}) != 58:
        raise ValueError('AES API probe population drift')
    return cases


def diagnostic_matches(result, code, source):
    errors = []
    try:
        for line in result.stderr.splitlines():
            message = json.loads(line)
            if message.get('$message_type') != 'diagnostic':
                continue
            if message.get('level', '').startswith('error'):
                if (message.get('code') is None and not message.get('spans')
                        and message.get('message', '').startswith('aborting due to ')):
                    continue  # rustc summary, not an independent diagnostic
                errors.append(message)
    except (ValueError, AttributeError):
        return False
    return (result.returncode == 1 and len(errors) == 1
            and (errors[0].get('code') or {}).get('code') == code
            and any(s.get('is_primary') and s.get('file_name') == str(source)
                    for s in errors[0].get('spans', [])))


def run_probes(toolchain, directory, env, *, cases=None, features='hazmat-aes-block',
               package='brynja-crypto', label='AES_API'):
    cases = probes() if cases is None else cases
    library = package.replace('-', '_')
    build = verifier.run(['cargo', '+' + toolchain, 'build', '--locked', '--offline',
                          '-p', package, '--no-default-features', '--features', features, '--message-format=json'], env)
    artifacts = []
    for line in build.splitlines():
        if not line.startswith('{'):
            continue
        row = json.loads(line)
        if row.get('reason') == 'compiler-artifact' and row.get('target', {}).get('name') == library:
            artifacts.extend(Path(p) for p in row['filenames'] if p.endswith('.rlib'))
    if len(artifacts) != 1 or not artifacts[0].resolve().is_relative_to(directory.resolve()):
        raise ValueError('missing/ambiguous/private-target AES library artifact')
    dependencies = directory / 'target/debug/deps'
    if not dependencies.is_dir():
        raise ValueError('missing native dependency artifacts')
    source = directory / 'probe.rs'
    command = ['rustc', '+' + toolchain, '--edition=2024', '--crate-name', 'aes_probe',
               '--emit=metadata', '--error-format=json', '-o', str(directory / 'probe.rmeta'),
               '-L', 'dependency=' + str(dependencies),
               '--extern', library + '=' + str(artifacts[0]), str(source)]
    for name, negative, positive, code in cases:
        source.write_text(positive)
        verifier.run(command, env, directory)
        source.write_text(negative)
        result = subprocess.run(command, cwd=directory, env=env, text=True,
                                capture_output=True, timeout=60)
        if not diagnostic_matches(result, code, source):
            raise ValueError(f'{toolchain}/{name}: expected only {code}\n{result.stderr[-4000:]}')
        print(f'{label}_CASE: {toolchain} {name} {code}', flush=True)
    print(f'{label}_PASS: {toolchain} {len(cases)} paired probes', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('toolchain', choices=TOOLCHAINS)
    args = parser.parse_args()
    with verifier.cargo_environment.private_directory(verifier.ROOT) as temporary:
        directory = Path(temporary)
        env = verifier.environment(directory)
        env.update(RUSTUP_AUTO_INSTALL='0', CARGO_NET_OFFLINE='true')
        run_probes(args.toolchain, directory, env)


if __name__ == '__main__':
    main()
