#!/usr/bin/env python3
"""Compile the real safe owner/parser and reject mutations; no native claims.

Standalone development check, not a new release gate. Native OS admission is
covered separately by the explicitly ignored Windows unit campaign.
"""
import shutil
import subprocess
import tempfile
from pathlib import Path
import windows_enclave_image_pin_build as build
import windows_enclave_admission as admission

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'crates/brynja-crypto-cpu-std/src/windows_enclave'
MUTANTS = (
    ('image.rs', 'hash.as_bytes() == &policy.digest', 'hash.as_bytes().len() == policy.digest.len()'),
    ('image.rs', 'bytes(b, add(c, 24)?, 16)? == policy.family', 'bytes(b, add(c, 24)?, 16)?.len() == policy.family.len()'),
    ('image.rs', 'bytes(self.b, add(t, 8)?, 64)?.iter().all(|&x| x == 0)', 'bytes(self.b, add(t, 8)?, 64)?.len() == 64'),
    ('image.rs', 'u32_at(b, add(c, 8)?)? == 0', 'u32_at(b, add(c, 8)?)? <= 2'),
    ('engine.rs', 'self.driver.export(&mut public)?;', 'let _ = self.driver.export(&mut public);'),
    ('engine.rs', 'pub(super) fn abandon(&mut self) {\n        self.state = State::Quarantined;', 'pub(super) fn abandon(&mut self) {\n        self.state = State::Ready;'),
    ('engine.rs', 'self.driver.close()?;', 'let _ = self.driver.close();'),
    ('engine.rs', 'self.sequence.checked_add(1).ok_or(Error::Exhausted)?', 'self.sequence.wrapping_add(1)'),
    ('protocol.rs', 'input.len() > 1024 || sequence == 0', 'input.len() > 1024'),
)


def main():
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    if not target.endswith('linux-gnu'):
        raise ValueError('This mutation harness targets the portable Linux model, not native OS evidence')
    with tempfile.TemporaryDirectory(prefix='windows-owner-regression-') as tmp:
        directory = Path(tmp)
        build.dependencies(directory, target, testing=True)
        shutil.copytree(SOURCE, directory / 'windows_enclave')
        policy = dict(status='OWNER_REVIEWED', schema=1, profile='production', reviewer='test',
            source_commit='a'*40, sha256=[1]*32, family=[2]*16, image=[3]*16,
            version=1, security=1, policy=0, size=0x10000000, threads=1, minimum_import_security=[0,0])
        generated = admission.owner_policy_source(policy).replace('brynja_strict::enclave', 'crate::windows_enclave')
        (directory/'lib.rs').write_text('pub mod windows_enclave;\n'+generated)
        command = ['rustc', '+1.98.1', '--edition=2024', '--test', '-D', 'warnings',
            '-C', 'opt-level=2', '-L', 'dependency='+str(directory), '--extern',
            'brynja_hash_sha2='+str(directory/'libbrynja_hash_sha2.rlib'),
            str(directory/'lib.rs'), '-o', str(directory/'tests')]
        def run(success):
            result = subprocess.run(command, capture_output=True, text=True, timeout=120)
            if result.returncode:
                raise AssertionError('Compilation failure is not mutant rejection: '+result.stderr)
            result = subprocess.run([str(directory/'tests')], capture_output=True, text=True, timeout=60)
            if success:
                if result.returncode or '15 passed' not in result.stdout:
                    raise AssertionError(result.stdout+result.stderr)
            elif result.returncode == 0 or 'FAILED' not in result.stdout:
                raise AssertionError('Mutant survived or did not fail its tests: '+result.stdout+result.stderr)
        run(True)
        for name, before, after in MUTANTS:
            file = directory/'windows_enclave'/name
            original = file.read_text()
            if original.count(before) != 1:
                raise AssertionError('Stale mutation: '+before)
            try:
                file.write_text(original.replace(before, after))
                run(False)
            finally:
                file.write_text(original)
        run(True)
    print('Windows enclave owner: fifteen real-source tests; nine compiled admission/lifecycle mutants rejected')


if __name__ == '__main__':
    main()
