#!/usr/bin/env python3
"""Paired downstream compiler diagnostics for the AES-192/256 owners."""
import argparse
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('aes_api', Path(__file__).with_name('check-aes-api.py'))
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)


def probes():
    cases = []
    for bits, width, expanded in ((192, 24, 208), (256, 32, 240)):
        for cached in (False, True):
            owner = f'Aes{bits}{"Expanded" if cached else ""}Key'
            size = expanded if cached else width
            prefix = f'use brynja_crypto::aes::{{{owner},PublicCiphertext}};\n'
            start = prefix + f'fn main() {{ let mut s=[0;{size}]; let key={owner}::new(&[0;{width}],&mut s).unwrap(); '
            use = 'let _=key.encrypt_block(&[0;16],&mut [0;16]); '
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                negative = prefix + f"fn require<T: {bound}>() {{}} fn main() {{ require::<{owner}<'static>>(); }}"
                cases.append((owner + '-not-' + bound, negative, negative.replace(f'T: {bound}', 'T'), 'E0277'))
            for name, key_size, storage_size in (
                ('wrong-key-width', 16, size), ('short-storage', width, size - 1),
                ('long-storage', width, size + 1),
            ):
                negative = prefix + f'fn main() {{ let _={owner}::new(&[0;{key_size}],&mut [0;{storage_size}]); }}'
                cases.append((owner + '-' + name, negative, start + 'key.clear(); }', 'E0308'))
            for method in ('encrypt_block', 'decrypt_block', 'encrypt_block_public'):
                authority = ',PublicCiphertext::acknowledge()' if method.endswith('_public') else ''
                negative = start + f'let mut out=[0;16]; let _=key.{method}(&out,&mut out{authority}); }}'
                cases.append((owner + '-' + method + '-overlap', negative,
                              negative.replace('&out,&mut out', '&[0;16],&mut out'), 'E0502'))
            cases.extend([
                (owner + '-consumed', start + 'key.clear(); ' + use + '}', start + use + 'key.clear(); }', 'E0382'),
                (owner + '-live-storage', start + 's.fill(1); ' + use + '}', start + use + 'key.clear(); s.fill(1); }', 'E0499'),
                (owner + '-short-block', start + 'let _=key.encrypt_block(&[0;15],&mut [0;16]); }', start + use + '}', 'E0308'),
                (owner + '-short-output', start + 'let _=key.encrypt_block(&[0;16],&mut [0;15]); }', start + use + '}', 'E0308'),
                (owner + '-no-export', start + 'let _=key.expose(); }', start + use + '}', 'E0599'),
                (owner + '-public-ack', start + 'let _=key.encrypt_block_public(&[0;16],&mut [0;16]); }',
                 start + 'let _=key.encrypt_block_public(&[0;16],&mut [0;16],PublicCiphertext::acknowledge()); }', 'E0061'),
                (owner + '-no-public-decrypt', start + 'let _=key.decrypt_block_public(&[0;16],&mut [0;16]); }',
                 start + 'let _=key.decrypt_block(&[0;16],&mut [0;16]); }', 'E0599'),
                (owner + '-key-lifetime', prefix + f'fn main() {{ let key; {{ let mut s=[0;{size}]; key={owner}::new(&[0;{width}],&mut s).unwrap(); }} ' + use + '}', start + use + '}', 'E0597'),
            ])
    if len(cases) != 76 or len({row[0] for row in cases}) != 76:
        raise ValueError('wide AES probe population drift')
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('toolchain', choices=api.TOOLCHAINS)
    args = parser.parse_args()
    with api.verifier.cargo_environment.private_directory(api.verifier.ROOT) as temporary:
        directory = Path(temporary)
        env = api.verifier.environment(directory)
        env.update(RUSTUP_AUTO_INSTALL='0', CARGO_NET_OFFLINE='true')
        api.run_probes(args.toolchain, directory, env, cases=probes(), label='AES_WIDE_API')


if __name__ == '__main__':
    main()
