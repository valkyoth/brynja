"""Observe live Drop bodies and prove each missing clear fails in both profiles."""


def exercise(roots, env, run):
    # Trusted temporary Cargo packages only, never the working implementation.
    patch = '\n[patch.crates-io]\n' + '\n'.join(
        f'{name} = {{ path = "{root.as_posix()}" }}' for name, root in roots.items()) + '\n'
    cases = [
        ('brynja-crypto-cpu', 'src/hardened_execution/scratch.rs', 'Scratch', 'new', ['schedule', 'vectors']),
        ('brynja-hash-sha2', 'src/hardened/owner.rs', 'HardenedSha2Owner', 'empty', [
            'chaining_state', 'partial_input', 'message_length', 'phase', 'message_schedule',
            'block_copy', 'padding_block', 'output_staging']),
    ]
    for package, source, owner, constructor, fields in cases:
        root = roots[package]
        manifest = root / 'Cargo.toml'
        old_manifest = manifest.read_text()
        path = root / source
        original = path.read_text()
        marker = f'impl Drop for {owner} {{\n    fn drop(&mut self) {{\n        self.wipe();'
        if original.count(marker) != 1:
            raise ValueError('stale destructor observer')
        assertions = '\n'.join(f'        assert!(self.{field}.iter().all(|b| *b == 0), "live Drop region {field}");' for field in fields)
        instrumented = original.replace(marker, marker + '\n' + assertions)
        fill = '\n'.join(f'    value.{field}.fill(0xa5);' for field in fields)
        instrumented += f'\n#[test]\nfn observed_live_destructor() {{\n    let mut value = {owner}::{constructor}();\n{fill}\n    drop(value);\n}}\n'
        try:
            manifest.write_text(old_manifest + patch)
            path.write_text(instrumented)
            for profile in ([], ['--release']):
                command = ['cargo', 'test', '--offline', '--all-features', '--lib', *profile, 'observed_live_destructor']
                result = run(command, root, env)
                if '1 passed' not in result.stdout:
                    raise ValueError('Drop observer did not run')
                for field in fields:
                    before = f'clear_owned_region(&mut self.{field})'
                    if before not in instrumented:
                        raise ValueError('stale clearing mutant')
                    path.write_text(instrumented.replace(before, 'Ok::<(), ()>(())'))
                    result = run(command, root, env, success=False)
                    if 'live Drop region ' + field not in result.stdout:
                        raise ValueError('cleanup mutant failed without live observation: ' + result.stderr)
                    path.write_text(instrumented)
        finally:
            path.write_text(original)
            manifest.write_text(old_manifest)
    print('Ten live owned regions observed on Drop; twenty compiled clearing mutants rejected')


def kernel_faults(consumer, roots, env, run, extra, mode):
    cpu = roots['brynja-crypto-cpu']
    api = cpu / 'src/hardened_execution/mod.rs'
    tests = cpu / 'src/hardened_execution/tests.rs'
    old_api, old_tests = api.read_text(), tests.read_text()
    manifest = cpu / 'Cargo.toml'
    old_manifest = manifest.read_text()
    patch = '\n[patch.crates-io]\n' + '\n'.join(
        f'{name} = {{ path = "{root.as_posix()}" }}' for name, root in roots.items()) + '\n'
    probe = '''
#[test]
fn injected_hardened_kat_quarantines_owner() -> Result<(), std::string::String> {
    let mut count = 0;
    for kernel in [Kernel::X86Sha256, Kernel::ArmSha256, Kernel::ArmSha512] {
        let Ok(owner) = raw::Authority::new(kernel) else { continue; };
        assert_eq!(Session::from_static(&owner).err(), Some(Error::Quarantined));
        assert_eq!(owner.report().health, raw::Health::Quarantined);
        assert_eq!(owner.session().err(), Some(Error::Quarantined));
        count += 1;
    }
    assert!(count > 0);
    Ok(())
}
'''
    command = ['cargo', 'test', '--offline', '--all-features', '--lib', *extra, 'injected_hardened_kat']
    try:
        manifest.write_text(old_manifest + patch)
        tests.write_text(old_tests + probe)
        broken_answer = old_api.replace('Ok(state == expected)', 'Ok(core::hint::black_box(state == expected) && false)')
        for profile in ([], ['--release']):
            api.write_text(broken_answer)
            run([*command, *profile], cpu, env)
            for before, after in (
                ('if !session.known_answer(kernel)?', 'if false'),
                ('session.route.quarantine();', 'let _ = &session.route;'),
            ):
                api.write_text(broken_answer.replace(before, after))
                result = run([*command, *profile], cpu, env, success=False)
                if 'test result: FAILED' not in result.stdout:
                    raise ValueError('startup mutation failed before test')
    finally:
        api.write_text(old_api)
        tests.write_text(old_tests)
        manifest.write_text(old_manifest)
    # Prove real post-startup kernel entry rather than just a route label.
    marker = 'dispatch(kernel, state, block, guard.scratch)?;'
    poison = '''
        if block.get(..3) != Some(b"abc") { state.fill(0); } else {
            dispatch(kernel, state, block, guard.scratch)?;
        }
'''
    if marker not in old_api:
        raise ValueError('stale kernel poison')
    route = roots['brynja-hash-sha2'] / 'src/hardened_execution/route.rs'
    old_route = route.read_text()
    call = 'session.compress(wide, &mut owner.chaining_state, &owner.block_copy)?'
    replacement = 'let _ = session; if wide { compress64::compress(owner); } else { compress32::compress(owner); }'
    try:
        api.write_text(old_api.replace(marker, poison))
        for profile in ([], ['--release']):
            route.write_text(old_route)
            command = ['cargo', 'run', '--offline', *profile, *extra, '--', *mode]
            result = run(command, consumer, env, success=False)
            if 'acceptance failed:' not in result.stderr:
                raise ValueError('poison failed without algorithm rejection')
            if call not in old_route:
                raise ValueError('stale scalar substitution')
            route.write_text(old_route.replace(call, replacement))
            run(command, consumer, env)  # positive control bypasses poisoned CPU path
    finally:
        api.write_text(old_api)
        route.write_text(old_route)
    print('Actual hardened KAT, irreversible quarantine and post-startup kernel entry: PASS')
