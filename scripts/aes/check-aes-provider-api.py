#!/usr/bin/env python3
"""Paired compiler checks for optional provider bindings and independent opt-ins."""
import argparse
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('aes_api', Path(__file__).with_name('check-aes-api.py'))
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)

PREFIX = '''use brynja_crypto::aes::provider::{Aes128Backend,Aes128ProviderKey,Permissions};
use brynja_crypto::aes::PublicCiphertext;
use brynja_crypto::provider::{ExternalKey,OwnedKeyBackend,ProviderFailureKind};
struct Backend;
impl Aes128Backend for Backend {
 fn permissions(&self)->Permissions { Permissions::EncryptAndDecrypt }
 fn encrypt_block(&mut self,i:&[u8;16],o:&mut[u8;16])->Result<usize,ProviderFailureKind> { o.copy_from_slice(i); Ok(16) }
 fn decrypt_block(&mut self,i:&[u8;16],o:&mut[u8;16])->Result<usize,ProviderFailureKind> { o.copy_from_slice(i); Ok(16) }
}
'''
OWNED = '''impl OwnedKeyBackend for Backend {
 fn destroy_key(&mut self)->Result<(),ProviderFailureKind> { Ok(()) }
}
'''
START = PREFIX + 'fn main(){ let mut key=Aes128ProviderKey::new(Backend); '
CALL = 'let _=key.encrypt_block(&[0;16],&mut[0;16]); '


def aes128_probes():
    cases = []
    for owner in ('Aes128ProviderKey<Backend>', 'ExternalKey<Backend>'):
        for bound in ('Copy', 'Clone', 'core::fmt::Debug'):
            negative = PREFIX + f'fn require<T:{bound}>(){{}} fn main(){{require::<{owner}>();}}'
            cases.append((owner + '-' + bound, negative, negative.replace('T:' + bound, 'T'), 'E0277'))
        for bound, field in (('Send', 'std::rc::Rc<()>'), ('Sync', 'std::cell::Cell<u8>')):
            positive = PREFIX + f'fn require<T:{bound}>(){{}} fn main(){{require::<{owner}>();}}'
            negative = positive.replace('struct Backend;', f'struct Backend({field});')
            # Cell is Send but not Sync: allow transfer without requiring sharing.
            if bound == 'Send':
                positive = positive.replace('struct Backend;', 'struct Backend(std::cell::Cell<u8>);')
            cases.append((owner + '-' + bound, negative, positive, 'E0277'))
    cases += [
        ('borrowed-cannot-destroy', START + 'let _=key.destroy();}',
         OWNED + START + 'let _=key.destroy();}', 'E0599'),
        ('consumed-destroy', OWNED + START + 'let _=key.destroy();' + CALL + '}',
         OWNED + START + CALL + 'let _=key.destroy();}', 'E0382'),
        ('adapter-consumed', PREFIX + 'fn main(){let b=Backend; let _k=Aes128ProviderKey::new(b); let _=Aes128ProviderKey::new(b);}',
         PREFIX + 'fn main(){let b=Backend; let _k=Aes128ProviderKey::new(b);}', 'E0382'),
        ('no-key-export', START + 'let _=key.expose();}', START + CALL + '}', 'E0599'),
        ('no-backend-extraction', START + 'let _=key.into_inner();}', START + CALL + '}', 'E0599'),
        ('no-public-decryption', START + 'let _=key.decrypt_block_public(&[0;16],&mut[0;16],PublicCiphertext::acknowledge());}',
         START + CALL + '}', 'E0599'),
        ('public-ack-required', START + 'let _=key.encrypt_block_public(&[0;16],&mut[0;16]);}',
         START + 'let _=key.encrypt_block_public(&[0;16],&mut[0;16],PublicCiphertext::acknowledge());}', 'E0061'),
        ('no-handle-substitution', START + 'key.binding=ExternalKey::new(Backend);}',
         START + CALL + '}', 'E0616'),
        ('neutral-borrowed-cannot-destroy', PREFIX + 'fn main(){let _=ExternalKey::new(Backend).destroy();}',
         OWNED + PREFIX + 'fn main(){let _=ExternalKey::new(Backend).destroy();}', 'E0599'),
        ('live-output', START + 'let mut o=[0;16]; let b=key.encrypt_block(&[0;16],&mut o).unwrap(); o.fill(1); let _=b.expose();}',
         START + 'let mut o=[0;16]; let b=key.encrypt_block(&[0;16],&mut o).unwrap(); b.clear(); o.fill(1);}', 'E0499'),
    ]
    for method in ('encrypt_block', 'decrypt_block', 'encrypt_block_public'):
        ack = ',PublicCiphertext::acknowledge()' if method.endswith('_public') else ''
        negative = START + f'let mut o=[0;16]; let _=key.{method}(&o,&mut o{ack});}}'
        cases.append((method + '-overlap', negative, negative.replace('&o,&mut o', '&[0;16],&mut o'), 'E0502'))
    for input_size, output_size in ((15, 16), (16, 15)):
        negative = START + f'let _=key.encrypt_block(&[0;{input_size}],&mut[0;{output_size}]);}}'
        cases.append((f'width-{input_size}-{output_size}', negative, START + CALL + '}', 'E0308'))
    if len(cases) != 25 or len({case[0] for case in cases}) != 25:
        raise ValueError('provider API probe population drift')
    return cases


def probes():
    cases = []
    for bits in (128, 192, 256):
        def width(source):
            return source.replace('Aes128', f'Aes{bits}')
        cases.extend((f'{bits}/{width(name)}', width(negative), width(positive), code)
                     for name, negative, positive, code in aes128_probes())
        for other in (128, 192, 256):
            if other == bits:
                continue
            prefix = width(PREFIX)
            # One call-site error, rather than duplicate constructor/type errors.
            def binding(width):
                return (prefix + f'fn bind<B:brynja_crypto::aes::provider::Aes{width}Backend>(b:B){{'
                        f'let _=brynja_crypto::aes::provider::Aes{width}ProviderKey::new(b);}}'
                        'fn main(){bind(Backend);}')
            negative, positive = binding(other), binding(bits)
            cases.append((f'{bits}/reject-{other}-binding', negative, positive, 'E0277'))
    if len(cases) != 81 or len({case[0] for case in cases}) != 81:
        raise ValueError('provider family API probe population drift')
    return cases


def run(toolchain):
    for package, path in (('brynja-crypto', 'brynja_crypto'), ('brynja', 'brynja::crypto')):
        route = 'direct' if package == 'brynja-crypto' else 'facade'
        groups = [
            ('hazmat-aes-block,external-key-provider', 'full', probes()),
            ('external-key-provider', 'neutral', [
                ('provider-does-not-enable-aes',
                 'use brynja_crypto::aes::provider::Aes128ProviderKey; fn main(){}',
                 'fn main(){let _=brynja_crypto::provider::ExternalKey::new(());}', 'E0433'),
            ]),
            ('hazmat-aes-block', 'software', [
                ('aes-does-not-enable-provider',
                 'use brynja_crypto::aes::provider::Aes128ProviderKey; fn main(){}',
                 'fn main(){let _=brynja_crypto::aes::Aes128Key::new(&[0;16],&mut[0;16]);}', 'E0432'),
            ]),
            ('', 'default-off', [
                ('provider-default-off', 'use brynja_crypto::provider::ExternalKey; fn main(){}',
                 'fn main(){let _=brynja_crypto::SHA256_IMPLEMENTED;}', 'E0432'),
            ]),
        ]
        for features, group, cases in groups:
            rewritten = [(name, negative.replace('brynja_crypto', path),
                          positive.replace('brynja_crypto', path), code)
                         for name, negative, positive, code in cases]
            with api.verifier.cargo_environment.private_directory(api.verifier.ROOT) as temporary:
                directory = Path(temporary)
                env = api.verifier.environment(directory)
                env.update(RUSTUP_AUTO_INSTALL='0', CARGO_NET_OFFLINE='true')
                api.run_probes(toolchain, directory, env, cases=rewritten, features=features,
                               package=package, label=f'AES_PROVIDER_{route}_{group}')
    print(f'AES_PROVIDER_API_PASS: {toolchain} 168 paired probes; direct and facade; independent opt-ins', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('toolchain', choices=api.TOOLCHAINS)
    run(parser.parse_args().toolchain)
