"""Compiled scope/ownership and observable semantic mutations for SHA-2."""
from facade_tuplehash_probes import diagnostic
from facade_scoped_sha2 import require, check_result, shared

STATES = ('Sha224', 'Sha256', 'Sha384', 'Sha512', 'Sha512_224', 'Sha512_256', 'Sha512T')
MISUSE = (
    ('fn reuse(s:t::Sha256) { s.cancel(); let _=s.update(b"x"); }', 'E0382'),
    ('fn reuse(s:t::Sha512T) { let _=s.finalize_public(api::sha2::PublicDeclassification::acknowledge()); let _=s.parameter(); }', 'E0382'),
    ('fn escape(w:&mut t::Sha256Workspace) { let _=w.with(|s| s); }', None),
    ('fn escape(w:&mut t::Sha512TWorkspace) { let _=w.with(|s| s); }', None),
    ('fn overlap(w:&mut t::Sha256Workspace) { let _=w.with(|_| w.with(|_| ())); }', 'E0501'),
    ('fn overlap(w:&mut t::Sha512TWorkspace) { let _=w.with(|_| w.with(|_| ())); }', 'E0501'),
    ('fn public(s:t::Sha256) { let _=s.finalize_public(&mut [0;32]); }', 'E0061'),
    ('fn public(s:t::Sha512T) { let _=s.finalize_public(); }', 'E0061'),
    ('fn wrong() { let _=t::Sha256Workspace::new(api::sha2::execution::Execution::portable()); }', 'E0308'),
    ('fn convert(x:api::sha2::hardened_execution::GeneralSecretOutput) { let _:api::sha2::Sha512TDigest=x.digest; }', 'E0308'),
    ('fn lifetime() { let a=api::cpu::static_execution::Authority::new(api::cpu::static_execution::Kernel::X86Sha256).unwrap(); '
     'let w=t::Sha256Workspace::new(api::sha2::hardened_execution::Execution::from_static(&a).unwrap()).unwrap(); drop(a); drop(w); }', 'E0505'),
)


def negatives(api, consumer, package, cargo, env):
    path = consumer / 'src/lib.rs'
    original = path.read_text()
    count = 0
    try:
        for name in STATES:
            for suffix in ('', 'Workspace'):
                typename = 'api::sha2::hardened_execution::in_place::' + name + suffix
                api.source(consumer, package, f'pub fn present(_:Option<{typename}>) {{}}')
                api.run(cargo + ['check', '--offline', '--lib'], consumer, env)
                for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                    api.source(consumer, package, f'fn bound<T:{bound}>() {{}} fn probe() {{ bound::<{typename}>(); }}')
                    result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'], consumer, env, success=False)
                    require(diagnostic(result, 'E0277'), 'owner diagnostic')
                    count += 1
            for method in ('message_bytes()', 'check_additional_bits(0)', 'check_additional_bytes(0)'):
                api.source(consumer, package, 'use api::sha2::hardened_execution::in_place as t;\n'
                           f'fn query(s:t::{name}) {{ let _=s.{method}; }}')
                result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'], consumer, env, success=False)
                require(diagnostic(result, 'E0599'), 'scoped length/preflight exposure')
                count += 1
        for text, code in MISUSE:
            api.source(consumer, package, 'use api::sha2::hardened_execution::in_place as t;\n' + text)
            result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'], consumer, env, success=False)
            require(diagnostic(result, code) if code else result.returncode == 101 and 'lifetime may not live long enough' in result.stdout,
                    'scope/misuse diagnostic')
            count += 1
    finally:
        path.write_text(original)
    require(count == 102, 'negative population')
    print('PASS: scoped SHA-2: 102 compiled ownership/lifetime/classification/metadata rejections', flush=True)


MUTANTS = (
    ('in_place.rs', 'destination.copy_from_slice(&word.to_be_bytes());', 'destination.fill(0);', 2, 'mismatch'),
    ('in_place/general.rs', 'self.parameter.initial_words()', '[0;8]', 1, 'Mismatch'),
    ('in_place/general.rs', 'self.parameter.last_byte_mask()', '0xff', 1, 'Mismatch'),
    ('in_place.rs', 'brynja_core::copy_secret_region(destination, self.engine.owner.staged($size).ok_or(Error::OutputLength)?)?;',
     'let _ = destination;', 1, 'mismatch'),
    ('engine.rs', 'self.report.message_blocks = 0;', 'let _ = self.report.message_blocks;', 1, 'mismatch'),
    ('mod.rs', 'let guard = brynja_core::SecretRegionInitialization::begin(destination)?;\n    if actual != length {\n        return Err(Error::OutputLength);\n    }',
     'if actual != length { return Err(Error::OutputLength); }\n    let guard = brynja_core::SecretRegionInitialization::begin(destination)?;', 1, 'mismatch'),
)


def mutants(api, consumer, roots, cargo, env):
    for filename, before, after, count, error in MUTANTS:
        path = roots['brynja-hash-sha2'] / 'src/hardened_execution' / filename
        original = path.read_text()
        require(original.count(before) == count, 'mutation anchor: ' + filename)
        try:
            path.write_text(original.replace(before, after))
            api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
            shared.check_error(api.run([str(shared.shared.binary(env, True)), 'portable'], consumer, env, success=False), error)
        finally:
            path.write_text(original)
    api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
    check_result(api.run([str(shared.shared.binary(env, True)), 'portable'], consumer, env), ('Portable', 'Portable'))
    print('PASS: scoped SHA-2: six compiled IV/masking/output/reuse/error-clearing mutants rejected', flush=True)
