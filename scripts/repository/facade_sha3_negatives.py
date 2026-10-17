"""Compiled ordinary sponge public-input and ownership rejection probes."""
from facade_tuplehash_probes import diagnostic

STATES = ('Sha3_224', 'Sha3_256', 'Sha3_384', 'Sha3_512', 'Shake128', 'Shake256', 'Cshake128', 'Cshake256')
OWNERS = STATES + ('Shake128Reader', 'Shake256Reader', 'Cshake128Reader', 'Cshake256Reader', 'Execution', 'StaticSelection')


def classification():
    cases = []
    for name in STATES:
        customized = name.startswith('Cshake')
        setup = (f'let mut h = s::{name}::new(s::Execution::portable()' +
                 (', s::Public::new(b""), s::Public::new(b"S")' if customized else '') + ').unwrap(); '
                 'let bytes = &b"x"[..]; let bits = api::sha3::Fips202BitString::new(bytes, 8).unwrap(); '
                 'let mut output = [0;1]; let mut scratch = [0;1]; '
                 'let dest = api::sha3::Fips202Output::new(&mut output, 8).unwrap(); ')
        p, b = 's::Public::new(bytes)', 's::PublicBits::new(bits)'
        calls = [('h.update(INPUT)', 'bytes', p)]
        if customized:
            calls.append(('h.finalize_bits_xof(INPUT)', 'bits', b))
            for method, raw, wrapped in (('new', 'bytes', p), ('new_bits', 'bits', b)):
                for index in range(2):
                    inputs = [wrapped] * 2
                    inputs[index] = 'INPUT'
                    calls.append((f's::{name}::{method}(s::Execution::portable(), {", ".join(inputs)})', raw, wrapped))
            for method, raw, wrapped, output in (('hash_with_scratch', 'bytes', p, '&mut output'),
                                                ('hash_bits_with_scratch', 'bits', b, 'dest')):
                for index in range(3):
                    inputs = [wrapped] * 3
                    inputs[index] = 'INPUT'
                    calls.append((f's::{name}::{method}(s::Execution::portable(), {", ".join(inputs)}, {output}, &mut scratch)', raw, wrapped))
        elif name.startswith('Sha3_'):
            calls += [(f's::{name}::hash(s::Execution::portable(), INPUT)', 'bytes', p),
                      ('h.finalize_bits(INPUT)', 'bits', b),
                      (f's::{name}::hash_bits(s::Execution::portable(), INPUT)', 'bits', b)]
        else:
            calls += [(f's::{name}::hash_with_scratch(s::Execution::portable(), INPUT, &mut output, &mut scratch)', 'bytes', p),
                      ('h.finalize_bits_xof(INPUT)', 'bits', b),
                      (f's::{name}::hash_bits_with_scratch(s::Execution::portable(), INPUT, dest, &mut scratch)', 'bits', b)]
        cases.extend((setup, call, raw, wrapped) for call, raw, wrapped in calls)
    return cases


MISUSE = (
    ('let _: s::Public = (&b"x"[..]).into();', 'E0277'),
    ('let _: s::PublicBits = api::sha3::Fips202BitString::new(b"x", 8).unwrap().into();', 'E0277'),
    ('let _ = s::Public(b"x");', 'E0603'),
    ('let _ = s::PublicBits(api::sha3::Fips202BitString::new(b"x", 8).unwrap());', 'E0603'),
    ('let h = s::Shake128::new(s::Execution::portable()).unwrap(); let _ = h.finalize_xof(); let _ = h.report();', 'E0382'),
    ('let owner = host::sponge::Sponge::new(host::sponge::Mode::Portable).unwrap(); let mut h = owner.sha3_256().unwrap(); drop(owner); let _ = h.update(s::Public::new(b"x"));', 'E0505'),
    ('let _: s::Execution = s::Route::Portable.into();', 'E0277'),
)


def execute(api, consumer, package, cargo, env):
    path = consumer / 'src/lib.rs'
    original = path.read_text()
    count = 0

    def check(body, code=None):
        api.source(consumer, package, 'use api::sha3::execution as s;\n' + body)
        result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'],
                         consumer, env, success=code is None)
        if code:
            api.require(diagnostic(result, code), 'ordinary sponge rejection diagnostic: ' + code)

    try:
        cases = classification()
        api.require(len(cases) == 48 and len(OWNERS) == 14, 'ordinary sponge negative inventory')
        for setup, call, raw, wrapped in cases:
            for value, code in ((wrapped, None), (raw, 'E0308')):
                check('fn probe() {' + setup + 'let _ = ' + call.replace('INPUT', value) + ';}', code)
            count += 1
        for owner in OWNERS:
            check(f'pub fn present(_: Option<s::{owner}>) {{}}')
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                check(f'fn require<T:{bound}>() {{}} fn probe() {{ require::<s::{owner}>(); }}', 'E0277')
                count += 1
        for snippet, code in MISUSE:
            check('fn probe() {' + snippet + '}', code)
            count += 1
    finally:
        path.write_text(original)
    api.require(count == 125, 'ordinary sponge negative population')
    print(f'PASS: {package}: 125 ordinary sponge classification/ownership rejections with positive controls', flush=True)
