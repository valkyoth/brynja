#!/usr/bin/env python3
"""Adversarial structural mutations for SHA-1 candidate authority and isolation."""
import shutil
import tempfile
from pathlib import Path
import cpu_policy as policy

def main():
    policy.validate()
    c = policy.CPU
    e = 'crates/brynja-legacy-sha1/src/execution.rs'
    p = policy.ADAPTER+'src/execution/platform.rs'
    cases = [
        (c+'session/tests.rs', 'fn operational_callback_revokes_live_streams_without_recovery()', 'fn removed_callback_regression()'),
        (c+'session.rs', 'Self::create(backend, revalidate)', 'Self::create(backend, |_| true)'),
        (p, 'Sha1Backend::Aarch64Sha1, revalidate)', 'Sha1Backend::Aarch64Sha1, |_| true)'),
        (p, 'backend == Sha1Backend::Aarch64Sha1 && availability().is_ok()', 'availability().is_ok()'),
        (p, 'backend == Sha1Backend::Aarch64Sha1 && availability().is_ok()', 'backend == Sha1Backend::Aarch64Sha1'),
        (e, 'self.revoked.set(true);', 'self.revoked.set(false);'),
        (e, 'owner.quarantine();', ''),
        (e, 'Err(Sha1BackendError::MissingFeatures) if mode == Mode::Prefer', 'Err(_) if mode == Mode::Prefer'),
        (e, 'self.state.take();\n            return Err(error);', 'return Err(error);'),
        (e, 'pub fn finalize(mut self)', 'pub fn finalize(&mut self)'),
        (e, 'pub fn finalize_bits(mut self,', 'pub fn finalize_bits(&mut self,'),
        (c+'session.rs', 'let session = Sha1BackendSession::startup(backend, revalidate, ABC)?;\n        session.ensure_healthy()?;', 'let session = Sha1BackendSession::startup(backend, revalidate, ABC)?;'),
        (p, 'availability().map_err(Error::Unavailable)?;', ''),
        (p, 'target_os = "windows"', 'target_os = "freebsd"'),
        (p, '&& std::arch::is_aarch64_feature_detected!("sha2")', ''),
        (policy.ADAPTER+'src/execution/mod.rs', 'Err(Error::Unavailable(_)) if mode == Mode::Prefer', 'Err(_) if mode == Mode::Prefer'),
        ('scripts/sha1/check-sha1-cpu.py', "['python3','scripts/sha1/check-sha1-package.py','--execution'],", ''),
        ('scripts/zeroization/check-zeroization-miri.sh', 'run_miri -p brynja-legacy-sha1 --features execution --test execution revocation_empty_updates_capacity_and_finalization_fail_closed', ''),
        ('scripts/zeroization/check-zeroization-sanitizer.sh', '-p brynja-legacy-sha1 --features execution --test execution', '-p brynja-legacy-sha1 --test cpu'),
        (c+'session.rs', 'cfg!(all(feature = "cpu-evidence", brynja_sha1_cpu_evidence))', 'cfg!(any(test, all(feature = "cpu-evidence", brynja_sha1_cpu_evidence)))'),
        (c+'session.rs', 'all(feature = "cpu-evidence", brynja_sha1_cpu_evidence)', 'brynja_sha1_cpu_evidence'),
        (c+'session.rs', 'brynja_sha1_cpu_evidence', 'brynja_cpu_evidence'),
        (c+'session.rs', 'all(feature = "cpu-evidence", brynja_sha1_cpu_evidence)', 'feature = "cpu-evidence"'),
        ('scripts/sha1/check-sha1-cpu.py', "['python3','scripts/sha1/test-sha1-evidence-builds.py'],", ''),
        ('.github/CONTRIBUTING.md', 'Never persist', 'Persist'),
        ('scripts/README.md', 'Do not deploy evidence binaries.', ''),
        ('docs/legacy-sha1-acceleration.md', 'Cargo feature unification', ''),
        ('docs/legacy-sha1-acceleration.md', 'Plain byte slices cannot prove that input is public.', ''),
        (c+'session.rs','!backend.is_admitted()', 'backend.is_admitted()'),
        (c+'session.rs','return Err(Sha1BackendError::NotAdmitted)', 'return Err(Sha1BackendError::MissingFeatures)'),
        (c+'session.rs','require_architecture(backend)?;', ''),
        (c+'session.rs','if !revalidate(backend)', 'if false'),
        (c+'session.rs','if state != expected', 'if false'),
        (c+'session.rs','session.compress(&mut state, &block)?;', ''),
        (c+'session.rs','if !(self.revalidate)(self.backend)', 'if false'),
        (c+'session.rs','self.healthy.set(false);\n            return Err(Sha1BackendError::MissingFeatures)', 'self.healthy.set(true);\n            return Err(Sha1BackendError::MissingFeatures)'),
        (c+'session.rs','PhantomData<*mut ()>', 'PhantomData<()>'),
        (c+'session.rs','self.ensure_healthy()?;', ''),
        (c+'mod.rs','pub const fn is_admitted(self) -> bool {\n        false', 'pub const fn is_admitted(self) -> bool {\n        true'),
        (c+'mod.rs','mod x86_sha1;', 'pub mod x86_sha1;'),
        (c+'stream.rs','self.failed = true;', 'self.failed = false;'),
        (c+'stream.rs','self.owner.wipe();', ''),
        (c+'stream.rs','return self.fail(error)', 'return Err(error)'),
        (c+'stream.rs','pub fn finalize(mut self)', 'pub fn finalize(&mut self)'),
        (c+'stream.rs','pub fn finalize_bits(mut self,', 'pub fn finalize_bits(&mut self,'),
        (c+'stream.rs','self.owner.clear_block();', ''),
        (c+'stream.rs','if offset >= 56', 'if offset > 56'),
        (c+'x86_sha1.rs','enable = "sha,sse2"', 'enable = "sse2"'),
        (c+'aarch64_sha1.rs','enable = "neon,sha2"', 'enable = "neon"'),
        (policy.ADAPTER+'src/lib.rs','Err(RequiredAccelerationUnavailable)', 'Ok(Self::opportunistic())'),
        ('security/sha1-cpu-admissions.toml','x86-sha1 = "unadmitted"', 'x86-sha1 = "admitted"'),
        ('scripts/zeroization/check-zeroization-miri.sh', 'run_miri -p brynja-legacy-sha1 --features cpu --lib quarantined_model_clears_all_regions_without_instructions', ''),
        ('scripts/zeroization/check-zeroization-miri.sh', 'run_miri -p brynja-legacy-sha1 --features cpu --test cpu', ''),
        ('scripts/zeroization/check-zeroization-sanitizer.sh', '-p brynja-legacy-sha1 --features cpu --lib --test cpu', '-p brynja-legacy-sha1 --lib'),
    ]
    with tempfile.TemporaryDirectory(prefix='brynja-sha1-cpu-mutations-') as temp:
        root = Path(temp)
        for path in policy.BOUND + ['scripts/checks.sh','scripts/tag_gate.sh','crates/brynja-legacy-sha1/src/lib.rs', 'scripts/zeroization/check-zeroization-miri.sh', 'scripts/zeroization/check-zeroization-sanitizer.sh']:
            file = root/path
            file.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(policy.ROOT/path,file)
        policy.validate(root,hashes=False)
        for path, old, new in cases:
            file = root/path
            before = file.read_text()
            if old not in before: raise AssertionError('stale CPU mutation '+old)
            file.write_text(before.replace(old,new,1))
            try:
                try: policy.validate(root,hashes=False)
                except ValueError: pass
                else: raise AssertionError('accepted CPU regression '+old)
            finally: file.write_text(before)
    print(f'SHA-1 CPU rejects {len(cases)} authority, feature, quarantine, lifecycle and isolation mutations')

if __name__ == '__main__': main()
