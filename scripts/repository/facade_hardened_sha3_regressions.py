"""Compiled ownership and semantic mutation checks on extracted SHA-3 only."""
from facade_tuplehash_probes import diagnostic
from facade_keccak_cases import require_runtime_rejection
from facade_hardened_sha3 import require, check_result

OWNERS = ('Sha3_224', 'Sha3_256', 'Sha3_384', 'Sha3_512', 'Shake128', 'Shake256',
          'Cshake128', 'Cshake256', 'Reader', 'KeccakSession')
SCOPED = tuple('in_place::' + name + suffix
               for name in OWNERS[:8]
               for suffix in (('', 'Workspace') if name.startswith('Sha3') else ('', 'Workspace', 'Reader')))
MISUSE = (
    ('fn reuse(h:t::Sha3_256) { let _=h.finalize_secret(&mut [0;32]); let _=h.report(); }', 'E0382'),
    ('fn reuse(h:t::Shake128) { let _=h.finalize_xof(); let _=h.report(); }', 'E0382'),
    ('fn escape(w:&mut t::in_place::Shake128Workspace) { let _=w.with(|s| s); }', None),
    ('fn escape(w:&mut t::in_place::Cshake256Workspace) { let _=w.with(b"",b"",|s| s.finalize_xof()); }', None),
    ('fn overlap(w:&mut t::in_place::Sha3_256Workspace) { let _=w.with(|_| w.with(|_| ())); }', 'E0501'),
    ('fn public(s:t::in_place::Sha3_256) { let _=s.finalize_public(&mut [0;32]); }', 'E0061'),
    ('fn public(mut r:t::Reader) { let _=r.squeeze_public(&mut []); }', 'E0061'),
    ('fn public(x:t::HardenedSha3SecretOutput) { let _: &[u8]=x; }', 'E0308'),
)


def negatives(api, consumer, package, cargo, env):
    path = consumer / 'src/lib.rs'
    original = path.read_text()
    count = 0
    try:
        for owner in OWNERS + SCOPED:
            typename = 'api::sha3::hardened_execution::' + owner
            api.source(consumer, package, f'pub fn exists(_:Option<{typename}>) {{}}')
            api.run(cargo + ['check', '--offline', '--lib'], consumer, env)
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                api.source(consumer, package, f'fn require<T:{bound}>() {{}}\npub fn probe() {{ require::<{typename}>(); }}')
                result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'], consumer, env, success=False)
                require(diagnostic(result, 'E0277'), 'ownership diagnostic: ' + owner)
                count += 1
        for body, code in MISUSE:
            api.source(consumer, package, 'use api::sha3::hardened_execution as t;\n' + body)
            result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'], consumer, env, success=False)
            if code:
                require(diagnostic(result, code), 'misuse diagnostic: ' + code)
            else:
                require(result.returncode == 101 and 'lifetime may not live long enough' in result.stdout,
                        'scope escape diagnostic')
            count += 1
    finally:
        path.write_text(original)
    require(count == 158, 'negative population')
    print('PASS: hardened SHA-3: 158 trait/ownership/scope/classification rejections', flush=True)


MUTANTS = (
    ('fixed.rs', 'self.engine.finish(input, 0x06, 3)?;', 'self.engine.finish(input, 0x1f, 5)?;', 2,
     'corpus', 'recorded_vectors_owned_and_scoped'),
    ('engine.rs', 'self.session\n            .permute(&mut self.memory.lanes)\n            .map_err(Error::Backend)?;',
     'let _ = &self.memory.lanes;', 1, 'corpus', 'recorded_vectors_owned_and_scoped'),
    ('in_place.rs', 'brynja_core::copy_secret_region(output, buffer).map_err(|_| Error::SecretMemory)?;',
     'let _ = (output, buffer);', 1, 'corpus', 'recorded_vectors_owned_and_scoped'),
    ('reader.rs', 'let _ = clear_owned_region(self.0);', 'let _ = &self.0;', 1,
     'scoped', 'scoped_lifecycle_and_output_failures'),
    ('in_place/xof.rs', 'brynja_core::apply_secret_byte_mask(last, u8::MAX >> 8_u8.saturating_sub(valid), 0);',
     'let _ = last;', 1, 'corpus', 'recorded_vectors_owned_and_scoped'),
)


def mutants(api, consumer, roots, cargo, env):
    lane = dict(env, FACADE_SHA3_MODE='static', FACADE_SHA3_EXPECT='ready')
    for filename, before, after, count, test, name in MUTANTS:
        path = roots['brynja-hash-sha3'] / 'src/hardened/accelerated' / filename
        original = path.read_text()
        require(original.count(before) == count, 'mutation anchor: ' + filename)
        try:
            path.write_text(original.replace(before, after))
            command = cargo + ['test', '--offline', '--release', '--test', test]
            api.run(command + ['--no-run'], consumer, lane)
            result = api.run(command + [name, '--', '--exact'], consumer, lane, success=False)
            require_runtime_rejection(result, name)
        finally:
            path.write_text(original)
    for test in ('corpus', 'scoped'):
        result = api.run(cargo + ['test', '--offline', '--release', '--test', test, '--', '--nocapture'], consumer, lane)
        check_result(result, test, True)
    print('PASS: hardened SHA-3: five compiled domain/permutation/scoped-output/scratch/masking mutants rejected', flush=True)
