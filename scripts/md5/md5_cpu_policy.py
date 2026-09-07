"""Exact MD5 batch/SIMD boundary; hash bindings are not independent review."""
import hashlib
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEAF = 'crates/brynja-legacy-md5/'
CPU = LEAF+'src/cpu/'
BATCH = LEAF+'src/batch/'
ADAPTER = 'crates/brynja-legacy-md5-std/'
CPU_SOURCES = ('mod.rs','constants.rs','kat.rs','session.rs','session/tests.rs','x86_avx2_md5.rs','aarch64_neon_md5.rs')
BATCH_SOURCES = ('mod.rs','control.rs','owner.rs','vector.rs','tests.rs')
BOUND = [CPU+p for p in CPU_SOURCES]+[BATCH+p for p in BATCH_SOURCES]+[
    LEAF+'Cargo.toml',LEAF+'src/lib.rs',LEAF+'tests/cpu.rs',
    ADAPTER+'Cargo.toml',ADAPTER+'src/lib.rs',ADAPTER+'README.md',
    'assurance/md5-cpu-public-api/Cargo.toml','assurance/md5-cpu-public-api/Cargo.lock',
    'assurance/md5-cpu-public-api/src/main.rs','assurance/md5-cpu-public-api/src/packaged.rs',
    'assurance/legacy-hash-public-api/src/vectors.rs',
    'assurance/legacy-hash-public-api/fixtures/representative.txt',
    'assurance/legacy-hash-public-api/fixtures/archive-index.json',
    'scripts/md5/md5_cpu_policy.py','scripts/md5/check-md5-cpu.py','scripts/md5/test-md5-cpu.py',
    'scripts/md5/check-md5-package.py','scripts/md5/test-md5-evidence-builds.py',
    'scripts/md5/check-md5-cpu-codegen.sh','scripts/md5/check-md5-cpu-qemu.sh',
    'scripts/md5/capture-md5-cpu-native.py','scripts/md5/test-md5-native-capture.py',
    'docs/legacy-md5-acceleration.md','security/md5-cpu-admissions.toml',
]

def require(source,token):
    if re.sub(r'\s+','',token) not in re.sub(r'\s+','',source):
        raise ValueError('MD5 CPU boundary lost: '+token)

def validate(root=ROOT,hashes=True):
    for directory,expected in ((CPU,CPU_SOURCES),(BATCH,BATCH_SOURCES)):
        if sorted(p.relative_to(root/directory).as_posix() for p in (root/directory).rglob('*.rs'))!=sorted(expected):
            raise ValueError('MD5 batch/CPU source inventory differs')
    sources={p:(root/p).read_text() for p in BOUND}
    for p,text in sources.items():
        if (root/p).is_symlink(): raise ValueError('symlink source rejected')
        if p.endswith(('.rs','.py','.sh')) and len(text.splitlines())>500: raise ValueError('code exceeds 500 lines')
    session=sources[CPU+'session.rs']
    for token in ('require_architecture(backend)?;',
        'if !backend.is_admitted() && !cfg!(all(feature = "cpu-evidence", brynja_md5_cpu_evidence))',
        'return Err(Md5BackendError::NotAdmitted)', 'if !revalidate(backend)',
        'Self::construct(backend, revalidate, false)', 'PhantomData<*mut ()>',
        'session.compress(&mut states, &blocks)?', 'if corrupt_kat ||',
        '.take(backend.lane_width())', 'session.healthy.set(false)',
        'self.ensure_healthy()?;', 'if !(self.revalidate)(self.backend) { self.healthy.set(false); return Err(Md5BackendError::MissingFeatures); }'):
        require(session,token)
    if 'brynja_cpu_evidence' in session or 'brynja_sha1_cpu_evidence' in session:
        raise ValueError('unrelated evidence cfg enables MD5')
    if re.search(r'impl\s+Clone|#\[derive\([^]]*Clone',session):
        raise ValueError('session quarantine ownership became clonable')
    require(sources[CPU+'mod.rs'],'pub const fn is_admitted(self) -> bool { false }')
    require(sources[CPU+'mod.rs'],'Self::X86Avx2 => 8, Self::Aarch64Neon => 4')
    if 'pub mod' in sources[CPU+'mod.rs']: raise ValueError('public instruction module')
    for file,feature,instructions in (
        ('x86_avx2_md5.rs','avx2',('_mm256_add_epi32','_mm256_sllv_epi32','_mm256_srlv_epi32')),
        ('aarch64_neon_md5.rs','neon',('vaddq_u32','vshlq_u32','vld1q_u32','vst1q_u32'))):
        text=sources[CPU+file]
        require(text,f'#[target_feature(enable = "{feature}")]')
        for token in instructions: require(text,token)
        for forbidden in ('get_unchecked','extern "','asm!','alloc::','Vec<','Box<'):
            if forbidden in text: raise ValueError('unreviewed kernel capability')
    batch=sources[BATCH+'mod.rs']
    for token in ('pub const MAX_BATCH_LANES: usize = 8',
        'pub fn digest(mut self,', 'pub fn digest_with_backend(mut self,',
        'pub fn digest_public(mut self,','pub fn digest_secret<\'out>(mut self,',
        'SecretRegionInitialization::begin(output.as_flattened_mut())',
        'initialization.write(&lane.output_staging)', 'initialization.finish()',
        'session.ensure_healthy().map_err(|_| Md5BatchError::Backend)?; self.owner.commit_public(output);'):
        require(batch,token)
    hardened=batch.split('impl HardenedMd5Batch {',1)[1]
    if any(token in hardened for token in ('digest_with_backend','vector::','Md5BackendSession')):
        raise ValueError('hardened SIMD is not cleanup-qualified')
    if any(token in batch for token in ('impl Clone','derive(Clone','impl core::fmt::Debug')):
        # Only the secret-free report may derive Copy/Clone/Debug.
        if batch.count('derive(Clone')!=1 or 'impl Clone' in batch or 'impl core::fmt::Debug' in batch:
            raise ValueError('batch ownership became clonable or formattable')
    for token in ('lanes: [Md5Owner; 8]', 'core::array::from_fn(|_| Md5Owner::new())',
                  'finish_lane(lane, *input, 0, control, &mut report)?', 'control.charge(padding)?',
                  'if owner.buffered() >= 56 { 2 } else { 1 }', 'engine::finish(owner, tail)'):
        require(sources[BATCH+'owner.rs'],token)
    for token in ('checked_sub(blocks)', 'Err(Md5BatchError::Cancelled)', 'self.remaining = self.remaining.checked_sub(blocks).ok_or(Md5BatchError::WorkLimit)?'):
        require(sources[BATCH+'control.rs'],token)
    for token in ('session.ensure_healthy()', 'control.charge(width)?', 'prefix.checked_add(64)',
                  'session.compress(&mut states, &data)', 'finish_lane(lane, *input, prefix, control, &mut report)?',
                  'input.map_or(0, |bits| bits.split().0.len() / 64)', '.chunks_mut(width)'):
        require(sources[BATCH+'vector.rs'],token)
    for name in BATCH_SOURCES:
        text=sources[BATCH+name].split('#[cfg(test)]')[0]
        if name=='tests.rs': continue
        if re.search(r'\b(unsafe|alloc|std|Vec|Box|static)\b|\.(unwrap|expect)\(',text):
            raise ValueError('batch allocation/unchecked/global boundary changed')
    adapter=sources[ADAPTER+'src/lib.rs']
    for token in ('Err(RequiredAccelerationUnavailable)','ScalarNoExecutionAuthority',
                  'brynja_legacy_md5::Md5Batch::new().digest(inputs, output, control)',
                  'std::is_x86_feature_detected!("avx2")'):
        require(adapter,token)
    if 'unsafe' in adapter or 'from_runtime_detection' in adapter: raise ValueError('observation minted authority')
    admission=tomllib.loads(sources['security/md5-cpu-admissions.toml'])
    if admission['admission']!={'x86_64-avx2':'unadmitted','aarch64-neon':'unadmitted',
        'avx512':'not-implemented','riscv-vector':'not-implemented','hardened':'portable-only'}:
        raise ValueError('admission requires architectural review')
    for path,token in (
        ('scripts/checks.sh','python3 scripts/md5/check-md5-cpu.py'),
        ('scripts/checks.sh','python3 scripts/md5/test-md5-cpu.py'),
        ('scripts/tag_gate.sh','scripts/md5/check-md5-cpu-qemu.sh'),
        ('scripts/zeroization/check-zeroization-miri.sh','run_miri -p brynja-legacy-md5 --features cpu --lib'),
        ('scripts/zeroization/check-zeroization-sanitizer.sh','-p brynja-legacy-md5 --features cpu --lib --test cpu'),
        ('scripts/assurance/check-kani.sh','cargo kani -p brynja-legacy-md5 --features batch')):
        require((root/path).read_text(),token)
    if hashes:
        expected=tomllib.loads((root/'scripts/md5/md5-cpu-reviewed.toml').read_text())['files']
        if set(expected)!=set(BOUND): raise ValueError('CPU hash inventory differs')
        for p in BOUND:
            if hashlib.sha256((root/p).read_bytes()).hexdigest()!=expected[p]: raise ValueError('CPU source changed: '+p)

def inventory():
    return '[files]\n'+''.join(f'"{p}" = "{hashlib.sha256((ROOT/p).read_bytes()).hexdigest()}"\n' for p in BOUND)
