#!/usr/bin/env python3
"""Source-policy adversarial mutations; never substitute for executing tests."""
import shutil
import tempfile
from pathlib import Path
import md5_cpu_policy as policy

CASES = (
    (policy.CPU+'session.rs','brynja_md5_cpu_evidence','brynja_cpu_evidence'),
    (policy.CPU+'session.rs','all(feature = "cpu-evidence", brynja_md5_cpu_evidence)','any(test, feature = "cpu-evidence", brynja_md5_cpu_evidence)'),
    (policy.CPU+'session.rs','require_architecture(backend)?;',''),
    (policy.CPU+'session.rs','if !revalidate(backend)','if false'),
    (policy.CPU+'session.rs','session.compress(&mut states, &blocks)?;',''),
    (policy.CPU+'session.rs','if corrupt_kat','if false'),
    (policy.CPU+'session.rs','PhantomData<*mut ()>','PhantomData<()>'),
    (policy.CPU+'session.rs','pub struct Md5BackendSession','#[derive(Clone)]\npub struct Md5BackendSession'),
    (policy.CPU+'session.rs','self.ensure_healthy()?;',''),
    (policy.CPU+'session.rs','self.healthy.set(false);',''),
    (policy.CPU+'mod.rs','        false','        true'),
    (policy.CPU+'mod.rs','Self::X86Avx2 => 8','Self::X86Avx2 => 4'),
    (policy.CPU+'mod.rs','mod session;','pub mod session;'),
    (policy.CPU+'x86_avx2_md5.rs','enable = "avx2"','enable = "sse2"'),
    (policy.CPU+'x86_avx2_md5.rs','_mm256_sllv_epi32','broken_shift'),
    (policy.CPU+'aarch64_neon_md5.rs','enable = "neon"','enable = "sha2"'),
    (policy.CPU+'aarch64_neon_md5.rs','vshlq_u32','broken_shift'),
    (policy.BATCH+'mod.rs','pub const MAX_BATCH_LANES: usize = 8','pub const MAX_BATCH_LANES: usize = 16'),
    (policy.BATCH+'mod.rs','pub fn digest(\n        mut self,','pub fn digest(\n        &mut self,'),
    (policy.BATCH+'mod.rs','SecretRegionInitialization::begin(output.as_flattened_mut())','SecretRegionInitialization::begin(&mut [])'),
    (policy.BATCH+'mod.rs','.write(&lane.output_staging)','.write(&[])'),
    (policy.BATCH+'mod.rs','impl HardenedMd5Batch {','impl HardenedMd5Batch { /* Md5BackendSession */'),
    (policy.BATCH+'mod.rs','pub struct HardenedMd5Batch','#[derive(Clone)]\npub struct HardenedMd5Batch'),
    (policy.BATCH+'owner.rs','lanes: [Md5Owner; 8]','lanes: [Md5Owner; 4]'),
    (policy.BATCH+'owner.rs','control.charge(padding)?;',''),
    (policy.BATCH+'owner.rs','owner.buffered() >= 56','owner.buffered() >= 57'),
    (policy.BATCH+'owner.rs','engine::finish(owner, tail)','engine::finish_bytes(owner)'),
    (policy.BATCH+'control.rs','checked_sub(blocks)','wrapping_sub(blocks)'),
    (policy.BATCH+'control.rs','Err(Md5BatchError::Cancelled)','Ok(())'),
    (policy.BATCH+'vector.rs','control.charge(width)?;',''),
    (policy.BATCH+'vector.rs','.checked_add(64)','.checked_add(63)'),
    (policy.BATCH+'vector.rs','.compress(&mut states, &data)','.compress(&mut states, &[[0;64];8])'),
    (policy.ADAPTER+'src/lib.rs','Err(RequiredAccelerationUnavailable)','Ok(Self::opportunistic())'),
    ('security/md5-cpu-admissions.toml','"unadmitted"','"admitted"'),
    ('scripts/zeroization/check-zeroization-miri.sh','run_miri -p brynja-legacy-md5 --features cpu --lib','echo skipped'),
    ('scripts/zeroization/check-zeroization-sanitizer.sh','-p brynja-legacy-md5 --features cpu --lib --test cpu','-p brynja-legacy-md5 --lib'),
)

def main():
    policy.validate()
    extra=('scripts/checks.sh','scripts/tag_gate.sh','scripts/zeroization/check-zeroization-miri.sh',
           'scripts/zeroization/check-zeroization-sanitizer.sh','scripts/assurance/check-kani.sh')
    with tempfile.TemporaryDirectory(prefix='brynja-md5-cpu-mutations-') as directory:
        root=Path(directory)
        for relative in policy.BOUND+list(extra):
            path=root/relative
            path.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(policy.ROOT/relative,path)
        policy.validate(root,hashes=False)
        for path,old,new in CASES:
            file=root/path
            original=file.read_text()
            if old not in original: raise AssertionError('mutation anchor missing: '+path+': '+old)
            file.write_text(original.replace(old,new))
            try:
                try: policy.validate(root,hashes=False)
                except ValueError: pass
                else: raise AssertionError('accepted boundary mutation: '+path+': '+old)
            finally: file.write_text(original)
    print(f'MD5 batch/SIMD policy rejects {len(CASES)} ownership, budget, kernel, admission and dynamic-analysis regressions')

if __name__=='__main__': main()
