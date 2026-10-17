"""Compiled production KMAC ownership and behavior regressions."""
from facade_tuplehash_probes import diagnostic
from facade_keccak_cases import require_runtime_rejection
from facade_parallelhash_acceptance import binary
from facade_tuplehash_acceptance import route

OWNERS = ('Kmac128', 'Kmac256', 'KmacXof128', 'KmacXof256', 'Reader', 'KeccakSession')
SCOPED = tuple(f'in_place::{prefix}{width}{suffix}' for width in (128, 256)
               for prefix, suffixes in (('Kmac', ('', 'Workspace')), ('KmacXof', ('', 'Workspace', 'Reader')))
               for suffix in suffixes)
MISUSE = (
    ('struct Forged; impl k::HardenedState for Forged {}', 'E0277'),
    ('fn reuse(h:k::Kmac128) { let _=h.finalize_tag(&mut [0;32]); let _=h.report(); }', 'E0382'),
    ('fn borrow(h:&mut k::KmacXof128) { if let Ok(mut r)=h.finalize_xof() { let _=h.update(&[]); let _=r.squeeze_secret(&mut []); } }', 'E0499'),
    ('fn convert(x:api::kmac::KmacSecretOutput) { let _: &[u8]=x; }', 'E0308'),
    ('fn fake() { let _:k::Mode = true.into(); }', 'E0277'),
    ('fn reuse(h:k::in_place::Kmac128) { let _=h.finalize_secret(&mut [0;32]); let _=h.key_policy(); }', 'E0382'),
    ('fn overlap(w:&mut k::in_place::Kmac128Workspace) { let _=w.with(&[0;32],b"",|_|w.with(&[0;32],b"",|_|())); }', 'E0500'),
    ('fn public(r:&mut k::in_place::KmacXof256Reader) { let _=r.squeeze_public(&mut []); }', 'E0061'),
)


def negatives(api, consumer, package, cargo, env):
    path = consumer / 'src/lib.rs'
    original = path.read_text()
    count = 0
    try:
        for owner in OWNERS + SCOPED:
            typename = 'api::kmac::execution::' + owner
            api.source(consumer, package, f'pub fn present(_:Option<{typename}>) {{}}')
            api.run(cargo + ['check', '--offline', '--lib'], consumer, env)
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                api.source(consumer, package, f'fn require<T:{bound}>() {{}} fn probe() {{ require::<{typename}>(); }}')
                result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'], consumer, env, success=False)
                api.require(diagnostic(result, 'E0277'), 'KMAC trait diagnostic: ' + owner)
                count += 1
        for body, code in MISUSE:
            api.source(consumer, package, 'use api::kmac::execution as k;\n' + body)
            result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'], consumer, env, success=False)
            api.require(diagnostic(result, code), 'KMAC misuse diagnostic: ' + code)
            count += 1
    finally:
        path.write_text(original)
    api.require(count == 88, 'KMAC negative population')
    print(f'PASS: {package}: 88 KMAC ownership/classification negatives with type controls', flush=True)


ALGORITHM = (
    ('backend.rs', 'b"KMAC"', 'b"WRONG"'),
    ('backend.rs', 'dispatch!(self, update(bytes))', 'let _ = (self, bytes); Ok(())'),
    ('core_state.rs', 'if xof { 0 } else { bits }', 'if xof { bits } else { 0 }'),
    ('output.rs', 'difference.accumulate(actual, expected)', 'difference.accumulate(actual, actual); let _ = expected'),
)


def algorithm_mutants(api, consumer, roots, cargo, env, data, kernel, check_result, check_failure):
    for filename, before, after in ALGORITHM:
        path = roots['brynja-mac-kmac'] / 'src/execution' / filename
        original = path.read_text()
        api.require(original.count(before) == 1, 'KMAC algorithm mutation anchor')
        try:
            path.write_text(original.replace(before, after))
            api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
            # Domain/update/suffix mutants compute consistently wrong outputs;
            # the comparison mutant fails the negative verification check.
            wrong_output = filename != 'output.rs'
            result = api.run([str(binary(env, True)), 'portable'], consumer, env, data=data[0], success=wrong_output)
            if wrong_output:
                values = result.stdout.splitlines()
                api.require(len(values) == 268 and values != data[1] and
                    all(len(actual) == len(expected) and all(c in '0123456789abcdef' for c in actual)
                        for actual, expected in zip(values, data[1])) and
                    result.stderr.strip() == 'KMAC_EXECUTION_ROUTE: ' + route('portable', kernel), 'surviving/malformed algorithm mutant')
            else:
                check_failure(result, 'portable', kernel, 'Other', 'KMAC lifecycle: "incorrect tag accepted"')
        finally:
            path.write_text(original)
    api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
    check_result(api.run([str(binary(env, True)), 'portable'], consumer, env, data=data[0]), data[1], 'portable', kernel)
    print('PASS: KMAC: four compiled domain/update/suffix/verification mutants rejected', flush=True)


def cleanup_mutant(api, consumer, roots, cargo, env, scoped=False):
    relative = 'src/hardened_in_place/accelerated.rs' if scoped else 'src/execution/output.rs'
    path = roots['brynja-mac-kmac'] / relative
    original = path.read_text()
    before = 'let _ = ' + ('brynja_core::' if scoped else '') + 'clear_owned_region(self.0);'
    api.require(original.count(before) == 1, 'KMAC scratch mutation anchor')
    target = 'scoped' if scoped else 'execution'
    names = ('scoped_native_fixed_output_lifecycle', 'xof::scoped_native_xof_output_and_lifecycle') if scoped else (
        'portable_execution_tags_match_and_outputs_are_transactional',)
    try:
        path.write_text(original.replace(before, 'let _ = &self.0;'))
        for name in names:
            command = cargo + ['test', '--offline', '--release', '--test', target, name]
            api.run(command + ['--no-run'], consumer, env)
            require_runtime_rejection(api.run(command + ['--', '--exact'], consumer, env, success=False), name)
    finally:
        path.write_text(original)
    result = api.run(cargo + ['test', '--offline', '--release', '--test', target], consumer, env)
    api.require(f'test result: ok. {4 if scoped else 7} passed; 0 failed; 0 ignored;' in result.stdout, 'restored KMAC lifecycle population')
    print(f'PASS: KMAC: compiled {target} scratch clearing mutant rejected by {len(names)} tests', flush=True)


def fallback_mutant(api, consumer, roots, cargo, env, data, kernel, check_result, check_failure):
    path = roots['brynja-mac-kmac'] / 'src/execution/backend.rs'
    original = path.read_text()
    before = 'Mode::Prefer(Some(session)) | Mode::Require(Some(session)) => Some(session),'
    api.require(original.count(before) == 1, 'KMAC portable substitution anchor')
    try:
        path.write_text(original.replace(before,
            'Mode::Prefer(Some(session)) | Mode::Require(Some(session)) => { let _ = session; None },'))
        api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
        for mode in ('static', 'prefer'):
            result = api.run([str(binary(env, True)), mode], consumer, env, data=data[0], success=False)
            check_failure(result, mode, kernel, 'Other', 'execution selection: "actual keyed owner route differs from selected authority"')
    finally:
        path.write_text(original)
    api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
    for mode in ('static', 'prefer'):
        check_result(api.run([str(binary(env, True)), mode], consumer, env, data=data[0]), data[1], mode, kernel)
    print('PASS: KMAC: compiled portable substitution rejected in required/preferred routes', flush=True)
