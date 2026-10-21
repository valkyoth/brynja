"""Strict facade probes: only protected sessions, never raw hash construction."""
from hmac_acceptance import ALGORITHMS

PREFIX = '#![forbid(unsafe_code)]\nuse facade::hmac::*;\n'
FORBIDDEN = ('Algorithm', 'Hmac', 'Tag', 'SecretTag', 'execution', 'protected_memory',
             'macos_resident', 'Authority', 'worker', 'types', 'compiled')


def positive(compiled=False):
    owner = 'CompiledSession' if compiled else 'Session'
    return PREFIX + '\n'.join(
        f'pub fn p{index}(s:&mut {owner}<{identity}>) -> Result<Output<\'_, {identity}>, Error> '
        '{s.authenticate(b"key", b"message")}' for index, identity in enumerate(ALGORITHMS))


def negatives(compiled=False):
    owner = 'CompiledSession' if compiled else 'Session'
    for identity in ALGORITHMS:
        for value in (f'{owner}<{identity}>', f'Output<\'static, {identity}>'):
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                yield (f'fn bound<T:{bound}>(){{}} fn probe(){{bound::<{value}>();}}', 'E0277')
    for name in FORBIDDEN:
        yield (f'use facade::hmac::{name};', 'E0432')
    yield ('fn probe(){let _ = Sha256::start();}', 'E0599')
    yield (f'fn probe(mut s:{owner}<Sha256>) -> Result<Output<\'static,Sha256>,Error>'
           '{s.authenticate(b"key",b"message")}', 'E0515')
    yield (f'fn probe(s:&mut {owner}<Sha256>) -> Result<(),Error> {{'
           'let first=s.authenticate(b"key",b"a")?; let _second=s.authenticate(b"key",b"b")?;'
           'let _=first.expose(); Ok(())}', 'E0499')
    yield ('fn probe(o:Output<Sha256>){let _=o.declassify(&mut []);}', 'E0061')
    yield ('fn probe(o:Output<Sha256>)->Output<Sha224>{o}', 'E0308')
    yield ('fn probe(o:Output<Sha512T<129>>)->Output<Sha512T<130>>{o}', 'E0308')
    yield (f'fn probe(s:{owner}<Sha256>){{let _=s.{"inner" if compiled else "stack"};}}', 'E0616')
    if not compiled:
        for name in ('CompiledSession', 'Kernel'):
            yield (f'use facade::hmac::{name};', 'E0432')


def scalar_fixture(root):
    return (root / 'crates/brynja-strict/src/hmac_tests.rs').read_text().replace(
        'use crate::hmac::*;', 'use facade::hmac::*;')


def documentation(root):
    text = (root / 'crates/brynja-strict/README.md').read_text()
    section = text.split('### HMAC\n')[1].split('\n## ', 1)[0]
    if section.count('```rust\n') != 1:
        raise ValueError('strict HMAC README example population changed')
    example = section.split('```rust\n')[1].split('```')[0]
    example = example.replace('brynja_strict::', 'facade::').replace('\n# ', '\n')
    return '\npub fn readme_example() -> Result<(), facade::hmac::Error> {\n' + example + '}\n'
