"""Packaged hardened SHA-1 oracle, typed ownership and compiled regression checks."""
import importlib.util
import random
import subprocess


def prepare(root, consumer):
    # Compile AND execute both feature-gated README examples in the packaged
    # consumer, whose --all-features enables the two matching feature names.
    library = consumer / 'src/lib.rs'
    docs = ''
    for name, title in (('brynja-legacy-sha1', 'LeafReadme'), ('brynja-legacy-sha1-std', 'HostedReadme')):
        readme = (root / 'crates' / name / 'README.md').read_text()
        (consumer / (title + '.md')).write_text(readme)
        docs += f'\n#[doc = include_str!("../{title}.md")]\npub struct {title};\n'
    library.write_text(library.read_text() + docs)
    tests = consumer / 'tests'
    (tests / 'vectors').mkdir(parents=True)
    for name in ('hardened_execution.rs', 'vectors/nist.txt'):
        (tests / name).write_bytes((root / 'crates/brynja-legacy-sha1/tests' / name).read_bytes())
    (tests / 'hosted.rs').write_bytes((root / 'crates/brynja-legacy-sha1-std/tests/hardened_execution.rs').read_bytes())
    spec = importlib.util.spec_from_file_location('oracle', root / 'scripts/sha1/check-sha1-differential.py')
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    rng = random.Random(0x2442)
    rows = []
    for bits in sorted(set(range(1040)) | {rng.randrange(65537) for _ in range(96)}):
        data = bytearray(rng.randbytes((bits + 7) // 8))
        if bits % 8: data[-1] &= (255 << (8 - bits % 8)) & 255
        expected = bytes.fromhex(oracle.oracle(data, bits))
        valid = (bits - 1) % 8 + 1 if bits else 0
        rows.append(f'(&{list(data)}, {valid}, {list(expected)})')
    source = '''use brynja_legacy_sha1::{BitString, PublicDeclassification, Sha1Error,
 hardened_execution::{Executor, Mode, Error}};
#[test]
fn independent_hardened_bit_oracle() -> Result<(), Error> {
 let cases: &[(&[u8],u8,[u8;20])] = &[CASES];
 let hosted = brynja_legacy_sha1_std::hardened_execution::select(Mode::Prefer);
 assert!(hosted.is_ok());
 let mut owners = vec![Executor::portable(), Executor::for_compiled_target(Mode::Prefer)?];
 if let Ok(hosted) = hosted { owners.push(hosted); }
 for owner in owners {
  for (bytes, valid, expected) in cases {
   let bits = BitString::new(bytes,*valid).map_err(|_| Sha1Error::MessageTooLong)?;
   let mut public = [0xa5;20];
   owner.hash_bits_public(bits,&mut public,PublicDeclassification::acknowledge())?;
   assert_eq!(public,*expected);
   let mut secret = [0xa5;20];
   let output = owner.hash_bits_secret(bits,&mut secret)?;
   assert_eq!(output.expose(),expected);
   drop(output); assert_eq!(secret,[0;20]);
  }
 }
 Ok(())
}
'''
    (tests / 'oracle.rs').write_text(source.replace('CASES', ',\n'.join(rows)))
    print(f'Independent hardened SHA-1 oracle: {len(rows)} bit messages, public and secret destinations')


def negatives(consumer, environment):
    path = consumer / 'src/lib.rs'
    before = path.read_bytes()
    cases = []
    for owner in ('Authority', 'Executor', "Stream<'static>"):
        for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
            cases.append((f'fn check<T: {bound}>() {{}}\nfn use_it() {{ check::<brynja_legacy_sha1::hardened_execution::{owner}>(); }}', 'E0277'))
    cases.extend([
        ('fn use_it(s: &brynja_legacy_sha1::hardened_execution::Stream<\'_>) { let _ = s.check_additional_bits(u64::MAX); }', 'E0599'),
        ('fn use_it(s: &brynja_legacy_sha1::hardened_execution::Stream<\'_>) { let _ = s.check_additional_bytes(usize::MAX); }', 'E0599'),
        ('struct Fake; impl brynja_legacy_sha1::HardenedSha1State for Fake {}', 'E0277'),
        ('fn use_it(a: brynja_legacy_sha1::execution::Authority) { let _ = brynja_legacy_sha1::hardened_execution::Executor::with_authority(a); }', 'E0308'),
        ('fn use_it(a: brynja_legacy_sha1::hardened_execution::Report) { let _ = brynja_legacy_sha1::hardened_execution::Executor::with_authority(a); }', 'E0308'),
        ('fn use_it(a: &brynja_legacy_sha1::hardened_execution::Executor) { let _ = a.hash_public(b"x", &mut [0;20]); }', 'E0061'),
        ('fn use_it(a: &brynja_legacy_sha1::hardened_execution::Executor) -> Result<(), brynja_legacy_sha1::hardened_execution::Error> { let mut s=a.start()?; s.cancel(); s.update(b"x") }', 'E0382'),
        ('fn use_it(a: &brynja_legacy_sha1::hardened_execution::Executor) -> Result<(), brynja_legacy_sha1::hardened_execution::Error> { let mut s=a.start()?; drop(s.finalize_secret(&mut [0;20])?); s.update(b"x") }', 'E0382'),
        ('fn use_it(a: &brynja_legacy_sha1::hardened_execution::Executor) { let mut b=[0;20]; if let Ok(output)=a.hash_secret(b"x",&mut b) { let _ = output.clone(); } }', 'E0599'),
    ])
    try:
        for source, code in cases:
            path.write_text(source)
            result = subprocess.run(['cargo', 'check', '--locked', '--offline', '--all-features'],
                cwd=consumer, env=environment, text=True, capture_output=True, timeout=90)
            if result.returncode == 0 or f'error[{code}]' not in result.stderr:
                raise ValueError('hardened ownership rejection absent or wrong error: '+result.stderr[-2000:])
    finally:
        path.write_bytes(before)
    print(f'Packaged hardened ownership/classification negatives: {len(cases)} rejected')


def mutants(consumer, root, environment):
    crate = root / 'unpacked/brynja-legacy-sha1-0.1.0'
    cases = [
        ('src/hardened_execution/mod.rs', 'self.revoked.set(true);', 'self.revoked.set(false);'),
        ('src/hardened_execution/mod.rs', 'let _ = clear_owned_region(destination);', 'let _ = destination;'),
        ('src/hardened_execution/stream.rs', 'destination.copy_from_slice(&self.owner.output_staging);', 'let _ = destination;'),
        ('src/hardened_execution/stream.rs', 'output\n            .write(&self.owner.output_staging)', 'output\n            .write(&[0; 20])'),
        ('src/hardened_execution/engine.rs', 'if offset >= 56', 'if offset > 56'),
    ]
    for relative, original, replacement in cases:
        path = crate / relative
        before = path.read_text()
        if original not in before: raise ValueError('stale hardened compiled mutation: '+relative)
        try:
            path.write_text(before.replace(original, replacement))
            for profile in ([], ['--release']):
                result = subprocess.run(['cargo', 'test', '--locked', '--offline', '--all-features',
                    '--test', 'hardened_execution', *profile], cwd=consumer, env=environment,
                    text=True, capture_output=True, timeout=180)
                if result.returncode == 0 or 'test result: FAILED' not in result.stdout:
                    raise ValueError('hardened mutant survived or failed compilation: '+relative+'\n'+result.stderr[-2000:])
        finally:
            path.write_text(before)
    print(f'Hardened output/quarantine/padding compiled mutants: {2 * len(cases)} rejected')
    cleanup_mutants(consumer, crate, root)


def cleanup_mutants(consumer, crate, root):
    import hardened_codegen as codegen
    previous_root = codegen.ROOT
    members = [p.name for p in (root / 'unpacked').iterdir() if p.is_dir()]
    manifest = '[workspace]\nresolver="3"\nmembers=[' + ','.join('"unpacked/'+name+'"' for name in sorted(members)) + ']\n[patch.crates-io]\n'
    for member in sorted(members):
        name = member.rsplit('-', 1)[0]
        manifest += f'{name} = {{ path="unpacked/{member}" }}\n'
    (root / 'Cargo.toml').write_text(manifest)
    (root / 'Cargo.lock').write_bytes((consumer / 'Cargo.lock').read_bytes())
    subprocess.run(['cargo', 'generate-lockfile', '--offline'], cwd=root, check=True, timeout=60)
    codegen.ROOT = root
    cases = [('src/owner.rs', f'let _ = clear_owned_region(&mut self.{region});')
             for region in ('chaining_state', 'block', 'schedule', 'message_length', 'buffered', 'output_staging')]
    cases += [('src/cpu/secret.rs', 'let _ = clear_owned_region(&mut self.lanes);'),
              ('src/cpu/secret.rs', 'self.wipe();'),
              ('src/cpu/secret.rs', 'self.owner.wipe();'),
              ('src/hardened_execution/stream.rs', 'self.state.owner.wipe();')]
    # Cross-compile without executing instructions; deterministic on every host.
    target = subprocess.check_output(['rustc', '-vV'], text=True)
    target = next(line.removeprefix('host: ') for line in target.splitlines() if line.startswith('host: '))
    if target not in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'aarch64-apple-darwin'):
        # CI runs the native compiler mutation campaign in its Linux repository
        # lane; other package consumers still run every ownership/runtime mutant.
        codegen.ROOT = previous_root
        return
    try:
        codegen.compile_and_check(root / 'cleanup', '1.98.1', target)
        for relative, original in cases:
            path = crate / relative
            before = path.read_text()
            prefix, body = ('', before)
            if relative == 'src/owner.rs':
                prefix, body = before.split('pub(crate) fn wipe(&mut self) {', 1)
                prefix += 'pub(crate) fn wipe(&mut self) {'
            if body.count(original) != 1: raise ValueError('stale cleanup mutation: '+original)
            try:
                path.write_text(prefix + body.replace(original, ''))
                try:
                    codegen.compile_and_check(root / 'cleanup', '1.98.1', target)
                except (ValueError, codegen.flow.MirCleanupFlowError):
                    pass
                else:
                    raise AssertionError('compiled cleanup removal survived: '+original)
            finally:
                path.write_text(before)
    finally:
        codegen.ROOT = previous_root
    print(f'Compiled source-owner and scratch cleanup removals: {len(cases)} rejected')
