"""Compiled cSHAKE/hosted ownership, classification and fault regressions."""


def run(consumer, roots, env, execute):
    main = consumer / 'src/main.rs'
    original = main.read_text()
    cases = []
    for name in ('Cshake128', 'Cshake256'):
        setup = ('let mut h = api::NAME::new(api::Execution::portable(), api::Public::new(b""), api::Public::new(b"S")).unwrap(); '
                 'let bytes = &b"x"[..]; let bits = brynja_hash_sha3::Fips202BitString::new(bytes, 8).unwrap(); '
                 'let mut out = [0;1]; let mut scratch = [0;1]; '
                 'let dest = brynja_hash_sha3::Fips202Output::new(&mut out, 8).unwrap(); ')
        p, b = 'api::Public::new(bytes)', 'api::PublicBits::new(bits)'
        calls = [(f'h.update(INPUT)', 'bytes', p), ('h.finalize_bits_xof(INPUT)', 'bits', b)]
        for method, raw, classified in (('new', 'bytes', p), ('new_bits', 'bits', b)):
            calls += [(f'api::NAME::{method}(api::Execution::portable(), INPUT, {classified})', raw, classified),
                      (f'api::NAME::{method}(api::Execution::portable(), {classified}, INPUT)', raw, classified)]
        for method, raw, classified, output in (('hash_with_scratch', 'bytes', p, '&mut out'),
                                              ('hash_bits_with_scratch', 'bits', b, 'dest')):
            for index in range(3):
                inputs = [classified]*3
                inputs[index] = 'INPUT'
                calls.append((f'api::NAME::{method}(api::Execution::portable(), {", ".join(inputs)}, {output}, &mut scratch)', raw, classified))
        for call, raw, classified in calls:
            cases.append((setup.replace('NAME', name), call.replace('NAME', name), raw, classified))
    try:
        for setup, call, raw, classified in cases:
            for value, accepted in ((raw, False), (classified, True)):
                main.write_text(original + '\nfn classification() {' + setup + 'let _ = ' + call.replace('INPUT', value) + ';}\n')
                result = execute(['cargo', 'check', '--offline'], consumer, env, accepted)
                if not accepted and 'error[E0308]' not in result.stderr:
                    raise ValueError('cSHAKE negative failed for unrelated reason: ' + result.stderr)
        for snippet, diagnostic in (
            ('let h = api::Cshake128::new(api::Execution::portable(), api::Public::new(b""), api::Public::new(b"S")).unwrap(); let _ = h.finalize_xof(); let _ = h.report();', 'E0382'),
            ('fn send<T: Send>() {} send::<api::Cshake128Reader>();', 'E0277'),
            ('fn sync<T: Sync>() {} sync::<api::Cshake256>();', 'E0277'),
            ('let h = api::Cshake256::new(api::Execution::portable(), api::Public::new(b""), api::Public::new(b"S")).unwrap(); let _ = h.clone();', 'E0599'),
            ('let _ = brynja_hash_sha3::HardenedCshake128::new(api::Execution::portable());', 'E0061'),
            ('let host = hosted::Sponge::new(hosted::Mode::Portable).unwrap(); let mut h = host.cshake128(api::Public::new(b""), api::Public::new(b"S")).unwrap(); drop(host); h.update(api::Public::new(b"x")).unwrap();', 'E0505'),
        ):
            main.write_text(original + '\nfn forbidden() {' + snippet + '}\n')
            result = execute(['cargo', 'check', '--offline'], consumer, env, False)
            if f'error[{diagnostic}]' not in result.stderr:
                raise ValueError('ownership negative failed for unrelated reason: ' + result.stderr)
    finally:
        main.write_text(original)
    print('cSHAKE: 24 raw input rejections, 24 controls and six ownership negatives passed')

    sources = roots['brynja-hash-sha3'] / 'src/execution'
    mutants = (
        ('cshake.rs', 'if self.customized', 'if false', None),
        ('cshake.rs', '(0x04, 3)', '(0x06, 3)', None),
        ('cshake.rs', 'function_name.0,', 'customization.0,', None),
        ('cshake.rs', 'setup_bytes = state.message_bytes', 'setup_bytes = 0', None),
        ('cshake.rs', 'state.update(&execution, bytes)', 'state.update(&Execution::portable(), bytes)', 'prefix_and_padding_faults_preserve_typed_errors'),
        ('cshake.rs', 'prefix_error(backend_error))?', 'Error::LengthOverflow)?', 'prefix_and_padding_faults_preserve_typed_errors'),
        ('cshake.rs', 'backend_error.unwrap_or(Error::PrefixEncoding)', 'backend_error.unwrap_or(Error::LengthOverflow)', 'prefix_encoding_errors_do_not_claim_length_overflow'),
        ('engine.rs', 'candidate.permute(execution, 2)?;', 'candidate.permute(&Execution::portable(), 2)?;', 'cshake_faults_keep_public_output_atomic'),
    )
    for filename, before, after, test in mutants:
        path = sources / filename
        source = path.read_text()
        if before not in source:
            raise ValueError('missing cSHAKE mutation site: ' + before)
        try:
            path.write_text(source.replace(before, after))
            for profile in ([], ['--release']):
                args = (['cargo', 'test', '--offline', '-p', 'brynja-hash-sha3', '--lib', *profile, test] if test
                        else ['cargo', 'run', '--offline', *profile, '--', 'portable'])
                result = execute(args, consumer, env, False)
                failed_before_execution = ('test result: FAILED' not in result.stdout) if test else ('acceptance failed:' not in result.stderr)
                if failed_before_execution:
                    raise ValueError('cSHAKE mutant failed before execution: ' + result.stderr)
        finally:
            path.write_text(source)
    host = roots['brynja-crypto-cpu-std'] / 'src/sponge.rs'
    original = host.read_text()
    try:
        host.write_text(original.replace('match session?', 'match session.unwrap_or(None)'))
        for profile in ([], ['--release']):
            result = execute(['cargo', 'test', '--offline', '-p', 'brynja-crypto-cpu-std', '--lib', *profile,
                              'hosted_sponge_error_never_authorizes_portable_fallback'], consumer, env, False)
            if 'test result: FAILED' not in result.stdout:
                raise ValueError('hosted fallback mutant failed before execution:\n' + result.stdout + result.stderr)
    finally:
        host.write_text(original)
    print('cSHAKE/hosted: eighteen debug/release algorithm, route and error mutants rejected')
