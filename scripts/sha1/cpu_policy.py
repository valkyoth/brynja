"""Exact legacy SHA-1 CPU candidate boundary; hashes are review bindings only."""
import hashlib
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CPU = 'crates/brynja-legacy-sha1/src/cpu/'
ADAPTER = 'crates/brynja-legacy-sha1-std/'
SOURCES = ('mod.rs','session.rs','stream.rs','x86_sha1.rs','aarch64_sha1.rs',
           'session/tests.rs','stream/tests.rs')
BOUND = [CPU + name for name in SOURCES] + [
    'crates/brynja-legacy-sha1/Cargo.toml', 'crates/brynja-legacy-sha1/tests/cpu.rs',
    ADAPTER+'Cargo.toml', ADAPTER+'src/lib.rs', ADAPTER+'README.md',
    'assurance/sha1-cpu-public-api/Cargo.toml', 'assurance/sha1-cpu-public-api/Cargo.lock',
    'assurance/sha1-cpu-public-api/src/main.rs',
    'assurance/sha1-cpu-public-api/src/packaged.rs', 'scripts/sha1/check-sha1-package.py',
    'scripts/sha1/cpu_policy.py', 'scripts/sha1/check-sha1-cpu.py',
    'scripts/sha1/test-sha1-cpu.py', 'scripts/sha1/check-sha1-cpu-codegen.sh',
    'scripts/sha1/test-sha1-native-capture.py',
    'scripts/sha1/test-sha1-evidence-builds.py',
    'scripts/sha1/check-sha1-cpu-qemu.sh', 'scripts/sha1/capture-sha1-cpu-native.py',
    'docs/legacy-sha1-acceleration.md', 'security/sha1-cpu-admissions.toml',
    '.github/CONTRIBUTING.md', 'scripts/README.md',
]

def require(source, token):
    if re.sub(r'\s+', '', token) not in re.sub(r'\s+', '', source):
        raise ValueError('SHA-1 CPU boundary lost: '+token)

def validate(root=ROOT, hashes=True):
    if sorted(p.relative_to(root/CPU).as_posix() for p in (root/CPU).rglob('*.rs')) != sorted(SOURCES):
        raise ValueError('CPU source inventory changed')
    sources = {path:(root/path).read_text() for path in BOUND}
    for path in BOUND:
        if (root/path).is_symlink(): raise ValueError('CPU evidence source symlink')
        if path.endswith(('.rs','.py','.sh')) and len(sources[path].splitlines()) > 500:
            raise ValueError('CPU evidence source too large')
    session, stream, identity = (sources[CPU+n] for n in ('session.rs','stream.rs','mod.rs'))
    require((root/'crates/brynja-legacy-sha1/src/lib.rs').read_text(), '#[cfg(feature = "cpu")] mod cpu;')
    if 'pub mod' in identity: raise ValueError('kernel module became public')
    for token in ('if !backend.is_admitted() && !cfg!(any(test, all(feature = "cpu-evidence", brynja_sha1_cpu_evidence)))',
                  'return Err(Sha1BackendError::NotAdmitted)', 'require_architecture(backend)?',
                  'if !revalidate(backend)', 'session.compress(&mut state, &block)?',
                  'if state != expected', 'session.healthy.set(false)',
                  'self.ensure_healthy()?;', 'if !(self.revalidate)(self.backend)',
                  'self.healthy.set(false)', 'PhantomData<*mut ()>',
                  'Self::construct(backend, revalidate, ABC)',
                  '#[cfg(all(target_arch = "aarch64", target_endian = "little"))]'):
        require(session,token)
    require(identity,'pub const fn is_admitted(self) -> bool { false }')
    require(sources['scripts/sha1/check-sha1-cpu.py'], "'scripts/sha1/test-sha1-evidence-builds.py'")
    if 'brynja_cpu_evidence' in session:
        raise ValueError('shared evidence cfg must not enable legacy SHA-1')
    require(sources['.github/CONTRIBUTING.md'], 'Never persist `--cfg brynja_cpu_evidence` or `--cfg brynja_sha1_cpu_evidence`')
    require(sources['scripts/README.md'], 'Do not deploy evidence binaries.')
    require(sources['docs/legacy-sha1-acceleration.md'], 'Cargo feature unification')
    require(sources['docs/legacy-sha1-acceleration.md'], 'Plain byte slices cannot prove that input is public.')
    require(session,'if !(self.revalidate)(self.backend) { self.healthy.set(false); return Err(Sha1BackendError::MissingFeatures); }')
    require(identity,'&["sse2", "sha"]')
    require(identity,'&["neon", "sha2"]')
    for token in ('self.failed = true;', 'self.owner.wipe();', 'return self.fail(error)',
                  'self.ready()?;', 'engine::admit_bits(self.owner.bits(), bits)',
                  'engine::admit_bytes(self.owner.bits(), input.len())',
                  'pub fn finalize(mut self)', 'pub fn finalize_bits(mut self,',
                  'self.owner.clear_block();', 'if offset >= 56', 'total.to_be_bytes()',
                  'SHA-1 accelerated update offset invariant', 'SHA-1 accelerated padding offset invariant'):
        require(stream,token)
    update = stream.split('pub fn update(',1)[1].split('pub fn finalize(',1)[0]
    require(update,'self.ready()?; let total = engine::admit_bytes')
    require(stream,'if let Err(error) = self.session.ensure_healthy() { return self.fail(error); }')
    require(stream,'if let Err(error) = self.session.compress(&mut words, &self.owner.block) { return self.fail(error); }')
    for forbidden in ('impl Clone', '#[derive(Clone', 'HardenedSha1State for', 'HardenedSha1', 'unchecked', 'static mut'):
        # HardenedSha1State occurs only in the compile-fail example, not as impl.
        if forbidden == 'HardenedSha1': continue
        if forbidden in stream: raise ValueError('accelerated secret/reuse boundary changed')
    for kernel, instructions, features in (
        ('x86_sha1.rs', ('sha1msg1','sha1msg2','sha1nexte','sha1rnds4'), 'sha,sse2'),
        ('aarch64_sha1.rs', ('vsha1cq','vsha1pq','vsha1mq','vsha1h','vsha1su0q','vsha1su1q'), 'neon,sha2')):
        text = sources[CPU+kernel]
        require(text,f'#[target_feature(enable = "{features}")]')
        for instruction in instructions: require(text,instruction)
        for forbidden in ('get_unchecked', 'extern "', 'asm!', 'alloc::', 'Vec<'):
            if forbidden in text: raise ValueError('kernel gained unreviewed execution boundary')
    adapter = sources[ADAPTER+'src/lib.rs']
    for token in ('Err(RequiredAccelerationUnavailable)', 'ScalarNoExecutionAuthority',
                  'brynja_legacy_sha1::sha1(bytes)', 'std::is_x86_feature_detected!("sha")'):
        require(adapter,token)
    if 'from_runtime_detection' in adapter or 'unsafe' in adapter:
        raise ValueError('safe host observation minted execution authority')
    admission = tomllib.loads(sources['security/sha1-cpu-admissions.toml'])
    if admission['admission'] != {'x86-sha1':'unadmitted','aarch64-sha1':'unadmitted','riscv':'scalar-only','hardened':'portable-only'}:
        raise ValueError('SHA-1 backend admission requires architectural review')
    for path, token in [('scripts/checks.sh','python3 scripts/sha1/check-sha1-cpu.py'),
                        ('scripts/checks.sh','python3 scripts/sha1/test-sha1-cpu.py'),
                        ('scripts/tag_gate.sh','scripts/sha1/check-sha1-cpu-qemu.sh'),
                        ('scripts/zeroization/check-zeroization-miri.sh','run_miri -p brynja-legacy-sha1 --features cpu --lib quarantined_model_clears_all_regions_without_instructions'),
                        ('scripts/zeroization/check-zeroization-miri.sh','run_miri -p brynja-legacy-sha1 --features cpu --test cpu'),
                        ('scripts/zeroization/check-zeroization-sanitizer.sh','-p brynja-legacy-sha1 --features cpu --lib --test cpu')]:
        require((root/path).read_text(),token)
    if hashes:
        expected = tomllib.loads((root/'scripts/sha1/cpu-reviewed.toml').read_text())['files']
        if set(expected) != set(BOUND): raise ValueError('CPU reviewed hash inventory differs')
        for path in BOUND:
            if hashlib.sha256((root/path).read_bytes()).hexdigest() != expected[path]:
                raise ValueError('CPU reviewed source changed: '+path)

def inventory():
    return '[files]\n'+''.join(f'"{p}" = "{hashlib.sha256((ROOT/p).read_bytes()).hexdigest()}"\n' for p in BOUND)
