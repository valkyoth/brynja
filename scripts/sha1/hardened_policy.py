"""Review-bound legacy secret SHA-1 execution; not independent verification."""
import hashlib
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEAF = 'crates/brynja-legacy-sha1/'
ADAPTER = 'crates/brynja-legacy-sha1-std/'
SOURCES = ('mod.rs', 'engine.rs', 'stream.rs', 'stream/tests.rs', 'ownership.rs', 'in_place.rs', 'in_place/tests.rs')
TOOLS = ('hardened_policy.py', 'hardened_package.py', 'hardened_codegen.py',
         'check-sha1-hardened.py', 'test-sha1-hardened.py', 'check-sha1-hardened-codegen.py',
         'check-sha1-package.py', 'check-sha1-differential.py', 'hardened_native.py',
         'capture-sha1-hardened-native.py', 'test-sha1-hardened-native.py',
         'check-sha1-hardened-asan.py', 'capture-sha1-cpu-native.py', 'check-sha1-hardened-native.py',
         'check-sha1-hardened-ci.py', 'test-sha1-hardened-ci.py', 'test-sha1-hardened-asan.py')
REVIEW = 'scripts/sha1/hardened-reviewed.toml'
SCOPED = ('state: Storage', "executor: &'authority Executor", 'owner: Sha1Owner',
          "action: impl for<'scope> FnOnce(Sha1<'scope, 'authority>) -> R",
          'self.state.clear();', 'self.owner.wipe(); self.active = false;',
          'guard.state.executor.ready()?;', 'guard.quarantine = false;',
          'scope.state.operate(|_, _| Ok(()))?;', 'scope.completed = true;',
          'if !self.completed { self.state.executor.quarantine(); }',
          'Err(Sha1Error::StateConsumed.into())',
          'let mut output = begin_output(destination)?;',
          'destination.copy_from_slice(&self.state.owner.output_staging);')
BORROWED_ENGINE = ('tail.split_borrowed()', 'copy_secret_region(destination, source)',
                   'core::slice::from_ref(last)',
                   'apply_secret_byte_mask(destination, 0xff, 0x80 >> valid)',
                   'copy_secret_region(&mut owner.output_staging, &owner.chaining_state)')
STRICT = {
    'mod.rs': ('require_target()?;', 'not(any(miri, kani))', 'target_os = "linux"',
               'target_env = "gnu"', 'target_pointer_width = "64"',
               'target_arch = "x86_64"', 'target_arch = "aarch64"', 'target_endian = "little"',
               'ProtectedStack::new(limits.stack_bytes, limits.max_stack_mapping_bytes)?',
               'ProtectedBytes::new(20, limits.max_output_mapping_bytes)?',
               'self.output.clear();', 'self.stack.run(||', 'result?; cancel.check()?;',
               'transaction.complete = true;', 'if !self.complete { self.output.clear(); }',
               'impl Drop for Digest', 'bits > u128::from(u64::MAX)',
               'chunks.len() > limits.max_chunks', 'bits > limits.max_message_bits'),
    'worker.rs': ('BitString::new(tail, valid_bits)', 'tail.split_borrowed()',
                  'chunk.chunks(4096)', 'checkpoint(cancel)?;',
                  'hardened_in_place::Sha1Workspace::new()',
                  'finalize_bits_secret(last, staged)',
                  'brynja_core::copy_secret_region(destination, secret.$borrow())'),
}


def inventory(root=ROOT):
    files = set('scripts/sha1/' + name for name in TOOLS)
    for crate in ('brynja-core', 'brynja-hash-core', 'brynja-legacy-sha1', 'brynja-legacy-sha1-std'):
        base = root / 'crates' / crate
        files.add(f'crates/{crate}/Cargo.toml')
        files.update(p.relative_to(root).as_posix() for p in (base / 'src').rglob('*.rs'))
    files.update((LEAF + 'tests/hardened_execution.rs', LEAF + 'tests/vectors/nist.txt',
                  ADAPTER + 'tests/hardened_execution.rs', ADAPTER + 'tests/vectors/nist.txt', 'Cargo.toml',
                  'assurance/register-cleanup/check.py',
                  'assurance/register-cleanup/check_sha1.py',
                  'assurance/register-cleanup/check_sha1_scalar.py',
                  'assurance/register-cleanup/sha1-scalar/Cargo.toml',
                  'assurance/register-cleanup/sha1-scalar/Cargo.lock',
                  'assurance/register-cleanup/sha1-scalar/src/lib.rs',
                  'assurance/register-cleanup/sha1-scalar/src/tests.rs',
                  'assurance/register-cleanup/sha1-scalar/src/tests/reference.rs',
                  'scripts/cryptography/mir_cleanup_flow.py'))
    return sorted(files)


def read(root, path):
    relative = Path(path)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('hardened source must be repository-relative')
    file = root / path
    if file.is_symlink() or not file.is_file() or file.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('invalid hardened SHA-1 source: ' + path)
    parent = file.parent
    while parent != root:
        if parent.is_symlink(): raise ValueError('symlinked hardened source parent')
        parent = parent.parent
    with file.open('rb') as handle:
        data = handle.read(4 * 1024 * 1024 + 1)
    if len(data) > 4 * 1024 * 1024: raise ValueError('source grew beyond bound')
    return data.decode('utf-8').replace('\r\n', '\n').replace('\r', '\n')


def hashes(root=ROOT):
    # Normalize platform checkout newlines, matching Python/Rust source checks.
    return {p: hashlib.sha256(read(root, p).encode()).hexdigest() for p in inventory(root)}


def require(source, token):
    if re.sub(r'\s+', '', token) not in re.sub(r'\s+', '', source):
        raise ValueError('hardened SHA-1 contract missing: ' + token)


def validate(root=ROOT, reviewed=True):
    if read(root, ADAPTER+'tests/vectors/nist.txt') != read(root, LEAF+'tests/vectors/nist.txt'):
        raise ValueError('packaged strict SHA-1 NIST corpus drifted')
    for file, tokens in STRICT.items():
        strict = read(root, ADAPTER+'src/strict_execution/'+file)
        for token in tokens: require(strict, token)
    manifest = tomllib.loads(read(root, ADAPTER+'Cargo.toml'))
    for name in ('brynja-core', 'brynja-crypto-cpu-std'):
        if manifest['dependencies'].get(name) != {'workspace': True, 'optional': True}:
            raise ValueError('strict SHA-1 protected resources must remain optional')
    directory = root / LEAF / 'src/hardened_execution'
    if sorted(p.relative_to(directory).as_posix() for p in directory.rglob('*.rs')) != sorted(SOURCES):
        raise ValueError('hardened SHA-1 source inventory changed')
    for name in SOURCES:
        source = read(root, LEAF + 'src/hardened_execution/' + name)
        if len(source.splitlines()) > 500: raise ValueError('hardened source exceeds 500 lines')
        if name not in ('stream/tests.rs', 'in_place/tests.rs') and re.search(r'\b(?:unsafe|Vec|Box|alloc::|std::)|\.(?:unwrap|expect)\(|\b(?:panic|todo|unimplemented)!', source):
            raise ValueError('hardened API gained low-level, allocating or panicking code')
    module = read(root, LEAF + 'src/hardened_execution/mod.rs')
    engine = read(root, LEAF + 'src/hardened_execution/engine.rs')
    for token in BORROWED_ENGINE: require(engine, token)
    require(module, 'mod engine; pub mod in_place; mod ownership; mod stream;')
    stream = read(root, LEAF + 'src/hardened_execution/stream.rs')
    scoped = read(root, LEAF + 'src/hardened_execution/in_place.rs')
    for token in SCOPED: require(scoped, token)
    if re.search(r'pub\s+(?:const\s+)?fn\s+(?:check_additional_bits|check_additional_bytes|reset|snapshot|bits|length)\b', scoped):
        raise ValueError('scoped hardened SHA-1 gained metadata/reopening API')
    secret = read(root, LEAF + 'src/cpu/secret.rs')
    methods = re.findall(r'\bpub\s+(?:(?:const|async)\s+)*fn\s+(\w+)', stream)
    if sorted(methods) != sorted(('update', 'finalize_public', 'finalize_bits_public',
                                'finalize_secret', 'finalize_bits_secret', 'cancel')):
        raise ValueError('hardened stream gained an unreviewed public query or operation')
    for token in ('pub struct Executor', 'Err(Sha1BackendError::MissingFeatures) if mode == Mode::Prefer',
                  'self.revoked.set(true)', 'let mut output = begin_output(destination)?;',
                  'Some(authority) => authority.compress(owner)', 'clear_owned_region(destination)',
                  'pub use crate::cpu::HardenedAuthority as Authority'):
        require(module, token)
    for token in ('impl crate::hardened::sealed::Sealed for Stream', 'impl HardenedSha1State for Stream',
                  'state: self, completed: false', 'operation.state.ready()?',
                  'self.state.owner.wipe()', 'self.state.failed = true', 'self.state.executor.quarantine()',
                  'pub fn cancel(self)', 'mut self, tail: BitString', 'begin_output(destination)?',
                  'destination.copy_from_slice(&self.owner.output_staging)'):
        require(stream, token)
    for token in ('PhantomData<*mut ()>', 'pub unsafe fn from_platform',
                  'super::session::require_architecture(backend)?', 'authority.compress(&mut owner)?',
                  'if owner.chaining_state !=', 'impl Drop for Scratch', 'self.wipe()',
                  'clear_owned_region(&mut self.lanes)', 'pub(crate) lanes: [u8; 16]',
                  'self.owner.wipe()', 'self.authority.quarantine()',
                  'self.healthy.set(false); if !(self.revalidate)(self.backend)',
                  'super::x86_sha1::compress_secret(operation.owner, &mut scratch)?',
                  'super::aarch64_sha1::compress_secret(operation.owner, &mut scratch)?'):
        require(secret, token)
    for name in ('x86_sha1.rs', 'aarch64_sha1.rs'):
        text = read(root, LEAF + 'src/cpu/' + name)
        features = 'sha,sse2' if name == 'x86_sha1.rs' else 'neon,sha2'
        require(text, '#[target_feature(enable = "'+features+'")] pub(super) unsafe fn compress_secret(')
        kernel = text.split('pub(super) unsafe fn compress_secret', 1)[1]
        for token in ('owner.schedule', 'scratch.wipe()', 'Result<(),'):
            require(kernel, token)
        if re.search(r'let(?:mut)?\w+=\[[^\]]*;', re.sub(r'\s+', '', kernel)):
            raise ValueError('secret kernel gained an unowned temporary array')
    for name in ('x86_sha1', 'aarch64_sha1'):
        opaque = read(root, LEAF + 'src/cpu/' + name + '/secret.rs')
        for token in ('#[inline(never)]', 'pub unsafe extern "C" fn compress(',
                      'state: &mut [u8; 20]', 'block: &[u8; 64]', 'schedule: &mut [u8; 320]',
                      'BRYNJA_SECRET_BEGIN', 'BRYNJA_REGISTER_ERASE', 'BRYNJA_SECRET_END',
                      'options(nostack)'):
            require(opaque, token)
        if opaque.count('asm!(') != 1 or re.search(r'\\b(?:lateout|nomem|readonly|pure)\\b', re.sub(r'//[^\\n]*', '', opaque)):
            raise ValueError('SHA-1 opaque boundary weakened')
    for file, features in ((LEAF, {'default': [], 'cpu': [], 'cpu-evidence': [], 'execution': ['cpu'], 'hardened-execution': ['cpu']}),
                           (ADAPTER, {'default': [], 'runtime-execution': ['brynja-legacy-sha1/execution'],
                                      'strict-execution': ['dep:brynja-core', 'dep:brynja-crypto-cpu-std', 'brynja-crypto-cpu-std/protected-memory'],
                                      'strict-acceleration': ['strict-execution', 'brynja-legacy-sha1/hardened-execution'],
                                      'runtime-hardened-execution': ['runtime-execution', 'brynja-legacy-sha1/hardened-execution']})):
        manifest = tomllib.loads(read(root, file+'Cargo.toml'))
        if manifest['features'] != features: raise ValueError('secret SHA-1 must remain explicit and default-off')
    ownership = read(root, LEAF+'src/hardened_execution/ownership.rs')
    platform = read(root, ADAPTER+'src/execution/platform.rs').split('pub(crate) fn construct_hardened()', 1)[1]
    require(platform, 'availability().map_err(Error::Unavailable)?;')
    require(platform, 'brynja_legacy_sha1::hardened_execution::Authority::from_platform( Sha1Backend::Aarch64Sha1, revalidate, )')
    require(read(root, ADAPTER+'src/hardened_execution.rs'), 'Err(Error::Unavailable(_)) if mode == Mode::Prefer')
    if ownership.count('```compile_fail') != 18: raise ValueError('hardened ownership doctest inventory changed')
    for owner in ('Executor', 'Authority', "Stream<'static>"):
        for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
            require(ownership, f'fn need<T: {bound}>() {{}} need::<{owner}>();')
    for command in ('python3 scripts/sha1/check-sha1-hardened.py', 'python3 scripts/sha1/test-sha1-hardened.py',
                    'python3 scripts/sha1/check-sha1-hardened-codegen.py'):
        require(read(root, 'scripts/checks.sh'), command)
    require(read(root, 'scripts/tag_gate.sh'), 'python3 scripts/sha1/check-sha1-hardened-native.py')
    for source in (module, secret):
        require(source, '**No runtime feature detection or migration protection is performed.**')
    require(read(root, LEAF+'src/cpu/secret/tests.rs'), 'std::env::var_os("BRYNJA_REQUIRE_HARDENED_SHA1").is_none()')
    require(read(root, LEAF+'tests/hardened_execution.rs'), 'std::env::var_os("BRYNJA_REQUIRE_HARDENED_SHA1").is_none() || compiled')
    ci = read(root, '.github/workflows/ci.yml').split('  hardened-sha1:\n', 1)[1].split('\n  host:', 1)[0]
    for token in ('runs-on: ${{ matrix.os }}', 'architecture: x86_64', 'architecture: aarch64',
                  '- os: ubuntu-latest', '- os: ubuntu-24.04-arm',
                  'run: python3 scripts/sha1/check-sha1-hardened-ci.py ${{ matrix.architecture }}'):
        if token not in [line.strip() for line in ci.splitlines()]:
            raise ValueError('missing active hardened SHA-1 CI setting: '+token)
    if 'continue-on-error' in ci or re.search(r'^\s+if:', ci, re.M):
        raise ValueError('required hardened SHA-1 CI lane must not skip or tolerate failure')
    driver = read(root, 'scripts/sha1/check-sha1-hardened-ci.py')
    for token in ('native.host.host(lane)', "RUSTFLAGS='-C target-feature='+features",
                  "BRYNJA_REQUIRE_HARDENED_SHA1='1'", "'--lib'", "'hardened_execution'",
                  'blocks=512', "'CI accelerated API'"):
        require(driver, token)
    require(read(root, 'scripts/sha1/check-sha1-hardened.py'), "'scripts/sha1/test-sha1-hardened-ci.py'")
    require(read(root, 'scripts/sha1/check-sha1-hardened.py'), "'scripts/sha1/test-sha1-hardened-asan.py'")
    sanitizer = read(root, 'scripts/sha1/check-sha1-hardened-asan.py')
    for token in ("env['ASAN_OPTIONS'] = 'detect_leaks=1:halt_on_error=1:exitcode=1'",
                  "env['LSAN_OPTIONS'] = 'exitcode=23'"):
        require(sanitizer, token)
    require(read(root, 'scripts/zeroization/check-zeroization-miri.sh'), 'run_miri -p brynja-legacy-sha1 --features hardened-execution --lib cpu::secret::tests')
    require(read(root, 'scripts/zeroization/check-zeroization-sanitizer.sh'), 'python3 scripts/sha1/check-sha1-hardened-asan.py')
    if reviewed:
        expected = tomllib.loads(read(root, REVIEW))
        if expected != {'schema': 1, 'regions': 7, 'files': hashes(root)}:
            raise ValueError('hardened SHA-1 review binding changed; reopen review')


def render(root=ROOT):
    return 'schema = 1\nregions = 7\n\n[files]\n' + ''.join(f'"{p}" = "{h}"\n' for p,h in hashes(root).items())
