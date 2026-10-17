"""Compiled public SHA-2 ownership and behavioral mutations in extracted crates."""
from facade_tuplehash_probes import diagnostic
from facade_parallelhash_acceptance import binary

STATES = ('Sha224', 'Sha256', 'Sha384', 'Sha512', 'Sha512_224', 'Sha512_256', 'Sha512T')
ORDINARY = (
    ('engine.rs', '*self = candidate;', 'let _ = candidate;', 1, 'mismatch'),
    ('engine.rs', 'self.finalize_inner(partial, bits,', 'self.finalize_inner(None, bits,', 1, 'mismatch'),
    ('general.rs', 'parameter.initial_words()', '[0; 8]', 1, 'Mismatch'),
    ('mod.rs', 'count.checked_add(1)', 'count.checked_add(0)', 1, 'mismatch'),
    ('route.rs', 'Inner::Portable => crate::compress::compress(state, block),', 'Inner::Portable => { let _ = (state, block); },', 1, 'mismatch'),
    ('route.rs', 'Inner::Portable => crate::compress64::compress(state, block),', 'Inner::Portable => { let _ = (state, block); },', 1, 'mismatch'),
)
HARDENED = (
    ('engine.rs', 'self.execution.compress(self.wide, guard.owner)?;', 'let _ = &guard.owner;', 1, 'mismatch'),
    ('engine.rs', 'self.execution.compress(self.wide, &mut self.owner)?;', 'let _ = &self.owner;', 1, 'mismatch'),
    ('general.rs', 'parameter.initial_words()', '[0; 8]', 1, 'Mismatch'),
    ('engine.rs', '0xff, 0x80 >> bits', '0xff, 0x80 >> bits.saturating_add(1)', 1, 'mismatch'),
    ('named.rs', 'brynja_core::copy_secret_region(\n                    destination,\n                    &self.engine.owner.output_staging[..$size],\n                )?;', '', 1, 'mismatch'),
    ('engine.rs', '.checked_add(1)', '.checked_add(0)', 2, 'mismatch'),
    ('general.rs', 'self.parameter.last_byte_mask()', '0xff', 1, 'Mismatch'),
    ('mod.rs', 'let guard = brynja_core::SecretRegionInitialization::begin(destination)?;\n    if actual != length {\n        return Err(Error::OutputLength);\n    }',
     'if actual != length { return Err(Error::OutputLength); }\n    let guard = brynja_core::SecretRegionInitialization::begin(destination)?;', 1, 'mismatch'),
)


def mutants(api, consumer, roots, cargo, env, hardened, check_error, check_result):
    cases = HARDENED if hardened else ORDINARY
    base = roots['brynja-hash-sha2'] / 'src' / ('hardened_execution' if hardened else 'execution')
    for filename, before, after, count, error in cases:
        path = base / filename
        original = path.read_text()
        api.require(original.count(before) == count, 'SHA-2 mutation anchor: ' + before)
        try:
            path.write_text(original.replace(before, after))
            api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
            check_error(api.run([str(binary(env, True)), 'portable'], consumer, env, success=False), error)
        finally:
            path.write_text(original)
    api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
    check_result(api.run([str(binary(env, True)), 'portable'], consumer, env), hardened, ('Portable', 'Portable'))
    print(f'PASS: SHA-2 {"hardened" if hardened else "ordinary"}: {len(cases)} compiled algorithm/output/accounting mutants rejected', flush=True)


def native_cases(hardened, wide):
    if hardened:
        return (
            ('hardened_execution/route.rs', (('session.compress(wide, &mut owner.chaining_state, &owner.block_copy)?',
                'let _ = (&session, wide, &owner);', 1),)),
            ('hardened_execution/route.rs', (('route: Route::Static(owner.report().kernel),', 'route: Route::Portable,', 1),
                ('inner: Inner::Cpu(cpu::Session::from_static(owner)?),', 'inner: Inner::Portable,', 1))),
        )
    cases = [('execution/route.rs', (('session.compress_sha256(PublicData::new(state), PublicData::new(block))?',
                'let _ = (session, state, block);', 2),)),
             ('execution/route.rs', (('route: self.route,', 'route: Route::Portable,', 1),
                ('Some(owner) => Inner::Static(owner.session()?),', 'Some(_owner) => Inner::Portable,', 1)))]
    if wide:
        cases.append(('execution/route.rs', (('session.compress_sha512(PublicData::new(state), PublicData::new(block))?',
                'let _ = (session, state, block);', 2),)))
    return tuple(cases)


def native_mutants(api, consumer, roots, cargo, env, hardened, wide, routes, check_error, check_result):
    cases = native_cases(hardened, wide)
    command = [str(binary(env, True)), 'static'] + ([] if wide else ['narrow'])
    for filename, replacements in cases:
        path = roots['brynja-hash-sha2'] / 'src' / filename
        original = path.read_text()
        changed = original
        for before, after, count in replacements:
            api.require(changed.count(before) == count, 'SHA-2 native mutation anchor')
            changed = changed.replace(before, after)
        try:
            path.write_text(changed)
            api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
            check_error(api.run(command, consumer, env, success=False), 'mismatch')
        finally:
            path.write_text(original)
    api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
    check_result(api.run(command, consumer, env), hardened, routes)
    print(f'PASS: SHA-2 {"hardened" if hardened else "ordinary"}: {len(cases)} native no-op/portable-downgrade mutants rejected; wide={wide}', flush=True)


def misuse(hardened):
    common = [
        ('let _: s::Execution = s::Route::Portable.into();', 'E0277'),
        ('let owner = api::cpu::static_execution::Authority::new(s::Kernel::X86Sha256).unwrap(); let e = s::Execution::from_static(&owner).unwrap(); drop(owner); let _ = s::Sha256::new(e);', 'E0505'),
    ]
    if hardened:
        return common + [
            ('let h = s::Sha256::new(s::Execution::portable()).unwrap(); h.cancel(); let _ = h.update(b"x");', 'E0382'),
            ('let _ = s::Sha256::new(api::sha2::execution::Execution::portable());', 'E0308'),
            ('let h = s::Sha256::new(s::Execution::portable()).unwrap(); let _ = h.finalize_public(&mut [0;32]);', 'E0061'),
            ('let _: api::sha2::Sha512TDigest = { let mut d = [0;1]; s::Sha512T::hash_secret(api::sha2::Sha512TBits::new(8).unwrap(), s::Execution::portable(), b"x", &mut d).unwrap().digest };', 'E0308'),
        ]
    return common + [
        ('let mut h = s::Sha256::new(s::Execution::portable()).unwrap(); let _ = h.finalize(); let _ = h.update(b"x");', 'E0382'),
        ('let _: api::sha2::Sha224Digest = s::Sha256::hash(s::Execution::portable(), b"x").unwrap().digest;', 'E0308'),
        ('fn secret<T:api::sha2::HardenedSha2State>() {} secret::<s::Sha256>();', 'E0277'),
    ]


def negatives(api, consumer, package, cargo, env, hardened):
    path = consumer / 'src/lib.rs'
    original = path.read_text()
    module = 'hardened_execution' if hardened else 'execution'
    count = 0

    def check(body, code=None):
        api.source(consumer, package, f'use api::sha2::{module} as s;\n' + body)
        result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'], consumer, env, success=code is None)
        if code:
            api.require(diagnostic(result, code), 'SHA-2 ownership diagnostic: ' + code)

    try:
        owners = STATES + ('Execution',) + (() if hardened else ('StaticSelection',))
        for owner in owners:
            check(f'pub fn present(_: Option<s::{owner}>) {{}}')
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                check(f'fn require<T:{bound}>() {{}} fn probe() {{ require::<s::{owner}>(); }}', 'E0277')
                count += 1
        if hardened:
            for owner in ('SecretOutput', 'GeneralSecretOutput'):
                check(f'pub fn present(_: Option<s::{owner}>) {{}}')
                for bound in ('Copy', 'Clone', 'core::fmt::Debug'):
                    check(f'fn require<T:{bound}>() {{}} fn probe() {{ require::<s::{owner}>(); }}', 'E0277')
                    count += 1
        for body, code in misuse(hardened):
            check('fn probe() {' + body + '}', code)
            count += 1
    finally:
        path.write_text(original)
    api.require(count == (52 if hardened else 50), 'SHA-2 ownership population')
    print(f'PASS: {package}: {count} {module} ownership/classification rejections with type controls', flush=True)
