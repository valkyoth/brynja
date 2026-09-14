"""Hardened MD5 ownership/source binding, not independent validation."""
import hashlib
import json
import re
import tomllib
from pathlib import Path
import md5_execution_policy as ordinary

ROOT = ordinary.ROOT
read = ordinary.read
REVIEW = 'scripts/md5/hardened-reviewed.json'
LEAF = 'crates/brynja-legacy-md5/'
HOST = 'crates/brynja-legacy-md5-std/'
CHECKS = {
    LEAF+'src/cpu/scratch.rs': tuple('clear_owned_region(self.'+field+'.as_flattened_mut())' for field in ('initial','words','work','temporary')) + ('impl Drop for Scratch', 'self.wipe();'),
    LEAF+'src/cpu/secret.rs': ('session::require_architecture(backend)?;', 'authority.ensure_healthy()?;',
        'authority.compress(&mut scratch)?;', 'if actual != &value.to_le_bytes()',
        'PhantomData<*mut ()>', 'self.healthy.set(false);', 'if !(self.revalidate)(self.backend)',
        'super::x86_secret::compress_secret(operation.scratch)?;',
        'super::arm_secret::compress_secret(operation.scratch)?;',
        'self.scratch.wipe();', 'self.authority.quarantine();'),
    LEAF+'src/batch/hardened_execution/mod.rs': ('owner: BatchOwner', 'executor: &\'a Executor',
        'mut self,', '_authority: PublicDeclassification', "OwnedSecretRegion<'out>",
        'SecretRegionInitialization::begin(output.as_flattened_mut())',
        'self.executor.ready()?;', 'if self.executor.required && authority.is_none()',
        'if self.executor.required && work.vector_blocks == 0',
        'vector::execute(&mut self.owner, inputs, control, a)?',
        'self.owner.commit_public(output);', 'self.executor.quarantine();',
        'let result = self.run_inner(inputs, control);',
        'guard.complete = matches!(result, Ok(_) | Err(Error::IneligibleWorkload) | Err(Error::Batch(Md5BatchError::WorkLimit | Md5BatchError::Cancelled | Md5BatchError::MessageTooLong)));'),
    LEAF+'src/batch/hardened_execution/vector.rs': ('let mut scratch = Scratch::new();',
        'authority.compress(&mut scratch)', 'finish_lane(lane, *input, prefix, control, &mut report)?;',
        'control.charge(width)?;', 'report.vector_blocks.checked_add(width)'),
    HOST+'src/hardened_execution/platform.rs': ('target_feature = "avx2"',
        'std::arch::is_aarch64_feature_detected!("neon")', 'Authority::from_platform(backend, revalidate)',
        'backend == Md5Backend::Aarch64Neon && availability() == Ok(backend)',
        'target_os = "linux"', 'target_os = "android"', 'target_os = "macos"', 'target_os = "ios"', 'target_os = "windows"'),
    'scripts/md5/check-md5-hardened-asan.py': (
        "env['ASAN_OPTIONS']='detect_leaks=1:halt_on_error=1:exitcode=1'",
        "env['LSAN_OPTIONS']='exitcode=23'", "env['BRYNJA_REQUIRE_HARDENED_MD5']='1'",
        "'-Zsanitizer=address -C target-feature=+avx2'", 'check=True'),
}
GATES = {
    'scripts/checks.sh': ('python3 scripts/md5/check-md5-hardened.py',
                         'python3 scripts/md5/check-md5-hardened-codegen.py',
                         'python3 scripts/md5/test-md5-hardened.py',
                         'python3 scripts/md5/test-md5-hardened-native.py'),
    'scripts/zeroization/check-zeroization-miri.sh': (
        'run_miri -p brynja-legacy-md5 --features hardened-execution --lib cpu::scratch::tests',
        'run_miri -p brynja-legacy-md5 --features hardened-execution --lib cpu::secret::tests',
        'run_miri -p brynja-legacy-md5 --features hardened-execution --test hardened_execution bounded_portable_cleanup_smoke'),
    'scripts/zeroization/check-zeroization-sanitizer.sh': ('python3 scripts/md5/check-md5-hardened-asan.py',),
    'scripts/tag_gate.sh': ('python3 scripts/md5/check-md5-hardened-native.py',),
    '.github/workflows/ci.yml': ('        run: python3 scripts/md5/check-md5-hardened-ci.py ${{ matrix.architecture }}',),
}


def paths(root=ROOT):
    names=set(ordinary.paths(root)) | set(CHECKS)
    names.update((LEAF+'tests/hardened_execution.rs',HOST+'tests/hardened_execution.rs',
        'docs/legacy-md5-hardened-execution.md'))
    names.update('assurance/md5-hardened-execution/'+n for n in ('Cargo.toml','Cargo.lock','src/main.rs'))
    names.update('scripts/md5/'+n for n in ('md5_hardened_policy.py','check-md5-hardened.py',
        'test-md5-hardened.py','md5_hardened_package.py','md5_hardened_codegen.py','check-md5-hardened-codegen.py'))
    names.update('scripts/md5/'+n for n in ('md5_hardened_native.py','capture-md5-hardened-native.py',
        'check-md5-hardened-native.py','check-md5-hardened-ci.py','test-md5-hardened-native.py'))
    return sorted(names)


def snapshot(root=ROOT):
    return {name: hashlib.sha256(ordinary.read(root,name)).hexdigest() for name in paths(root)}


def validate(root=ROOT, reviewed=True):
    for name,tokens in {**CHECKS, **GATES}.items():
        source=re.sub(r'\s+','',ordinary.read(root,name).decode())
        for token in tokens:
            if re.sub(r'\s+','',token) not in source: raise ValueError('hardened MD5 boundary: '+name+': '+token)
    for crate in (LEAF,HOST):
        features=tomllib.loads(ordinary.read(root,crate+'Cargo.toml').decode())['features']
        if features['default']: raise ValueError('hardened execution must be opt-in')
    leaf=tomllib.loads(ordinary.read(root,LEAF+'Cargo.toml').decode())
    host=tomllib.loads(ordinary.read(root,HOST+'Cargo.toml').decode())
    if leaf['features'].get('hardened-execution') != ['cpu'] or host['features'].get('runtime-hardened-execution') != ['brynja-legacy-md5/hardened-execution']:
        raise ValueError('hardened feature boundary')
    for name in paths(root):
        if name.endswith(('.rs','.py')) and len(ordinary.read(root,name).splitlines()) > 500:
            raise ValueError('hardened MD5 module review limit')
    for name in (LEAF+'src/cpu/scratch.rs',LEAF+'src/cpu/secret.rs',LEAF+'src/batch/hardened_execution/mod.rs',LEAF+'src/batch/hardened_execution/vector.rs'):
        source=ordinary.read(root,name).decode().split('#[cfg(test)]')[0]
        source='\n'.join(line for line in source.splitlines() if not line.lstrip().startswith('//'))
        if re.search(r'\b(?:ManuallyDrop|MaybeUninit|forget|transmute|Vec|Box)\b|\.(?:unwrap|expect)\(|\b(?:panic|todo|unimplemented)!',source):
            raise ValueError('hardened ownership bypass')
    vector=ordinary.read(root,LEAF+'src/batch/hardened_execution/vector.rs').decode()
    if 'Md5BackendSession' in vector or 'batch::vector' in vector:
        raise ValueError('secret state routed through ordinary scratch')
    if reviewed and json.loads(ordinary.read(root,REVIEW)) != {'schema':1,'sha256':snapshot(root)}:
        raise ValueError('hardened source review changed')


def write():
    validate(reviewed=False)
    (ROOT/REVIEW).write_text(json.dumps({'schema':1,'sha256':snapshot()},indent=2)+'\n')
