"""Compiled private-permit and domain-failure tests in temporary Cargo packages."""


def exercise(crates, env, run):
    cpu = crates['brynja-crypto-cpu']
    paths = {name: cpu / name for name in (
        'Cargo.toml', 'src/lib.rs', 'src/x86_sha512.rs',
        'src/static_execution/mod.rs', 'src/runtime_execution/mod.rs',
        'src/static_execution/x86_sha512_tests.rs', 'src/runtime_execution/tests.rs',
        'src/hardened_execution/mod.rs', 'src/hardened_execution/tests.rs')}
    originals = {name: path.read_text() for name, path in paths.items()}
    patch = '\n[patch.crates-io]\n' + '\n'.join(
        f'{name} = {{ path = "{root.as_posix()}" }}' for name, root in crates.items()) + '\n'
    base = ['cargo', '+1.98.1', 'test', '--offline', '--features',
            'hardened-execution,runtime-execution', '--lib', '--target', 'x86_64-unknown-linux-gnu']
    try:
        paths['Cargo.toml'].write_text(originals['Cargo.toml'] + patch)
        # These failures must be type errors, not missing symbols or linker errors.
        for snippet, diagnostic in (
            ('let _ = x86_sha512::Permit {};', 'private fields'),
            ('x86_sha512::compress(&mut [0; 8], &[0; 128]);', 'error[E0061]'),
            ('x86_sha512::compress_secret(&mut [0; 64], &[0; 128], &mut hardened_execution::scratch::Scratch::new());', 'error[E0061]'),
        ):
            paths['src/lib.rs'].write_text(originals['src/lib.rs'] + '\nfn forbidden() { ' + snippet + ' }\n')
            result = run(base + ['--no-run'], cpu, env, success=False)
            if diagnostic not in result.stderr:
                raise ValueError('permit negative failed for wrong reason: ' + result.stderr)
        paths['src/lib.rs'].write_text(originals['src/lib.rs'])
        common = '''
    let session = owner.session()?;
    let mut state = [7; 8];
    assert_eq!(session.compress_sha512(PublicData::new(&mut state), PublicData::new(&[0xa5;128])), Err(Error::InternalDomain));
    assert_eq!(state, [7;8]);
    assert_eq!(owner.report().health, Health::Quarantined);
    assert_eq!(session.compress_sha512(PublicData::new(&mut state), PublicData::new(&[0;128])), Err(Error::Quarantined));
    Ok(())
}
'''
        paths['src/static_execution/x86_sha512_tests.rs'].write_text(
            originals['src/static_execution/x86_sha512_tests.rs'] + '''
#[test]
fn injected_domain_revokes_static_owner() -> Result<(), Error> {
    let owner = Authority::new(Kernel::X86Sha512)?;
''' + common)
        paths['src/runtime_execution/tests.rs'].write_text(originals['src/runtime_execution/tests.rs'] + '''
#[test]
fn injected_domain_revokes_runtime_owner() -> Result<(), Error> {
    let mut owner = model();
    owner.kernel = Kernel::X86Sha512;
    owner.complete_startup(operations::known_answer(&owner));
''' + common)
        paths['src/hardened_execution/tests.rs'].write_text(originals['src/hardened_execution/tests.rs'] + '''
#[test]
fn injected_domain_clears_and_revokes_hardened_owner() -> Result<(), Error> {
    let owner = raw::Authority::new(Kernel::X86Sha512)?;
    let mut session = Session::from_static(&owner)?;
    session.scratch.schedule.fill(0xa5);
    session.scratch.vectors.fill(0xa5);
    let mut state = [7;64];
    assert_eq!(session.compress(true, &mut state, &[0xa5;128]), Err(Error::InternalDomain));
    assert_eq!(state, [7;64]);
    assert!(session.scratch.schedule.iter().all(|byte| *byte == 0));
    assert!(session.scratch.vectors.iter().all(|byte| *byte == 0));
    assert_eq!(owner.report().health, raw::Health::Quarantined);
    Ok(())
}
''')
        needle = 'permit.check()?;'
        if originals['src/x86_sha512.rs'].count(needle) != 2:
            raise ValueError('stale kernel fault injection')
        paths['src/x86_sha512.rs'].write_text(originals['src/x86_sha512.rs'].replace(
            needle, needle + '\n    if block.first() == Some(&0xa5) { return Err(Error::InternalDomain); }'))
        for profile in ([], ['--release']):
            command = base + profile + ['injected_domain']
            result = run(command, cpu, env)
            if '3 passed' not in result.stdout:
                raise ValueError('domain fault positive control skipped')
            for name, needle in (
                ('src/static_execution/mod.rs', 'if matches!(result, Err(Error::InternalDomain | Error::Quarantined)) {'),
                ('src/runtime_execution/mod.rs', 'if matches!(result, Err(Error::InternalDomain | Error::Quarantined)) {'),
                ('src/hardened_execution/mod.rs', 'if !self.completed {'),
            ):
                if originals[name].count(needle) != 1:
                    raise ValueError('stale quarantine mutation: ' + name)
                paths[name].write_text(originals[name].replace(needle, 'if false {'))
                result = run(command, cpu, env, success=False)
                if 'test result: FAILED' not in result.stdout:
                    raise ValueError('quarantine mutant failed before runtime')
                paths[name].write_text(originals[name])
    finally:
        for name, path in paths.items():
            path.write_text(originals[name])
    print('SHA512 private permits: three compiled negatives; domain faults: three routes, six quarantine mutants PASS')
