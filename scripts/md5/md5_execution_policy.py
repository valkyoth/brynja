"""Non-authorizing source/feature contract for ordinary operational MD5."""
import hashlib
import json
import re
import tomllib
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
REVIEW='scripts/md5/execution-reviewed.json'
LEAF='crates/brynja-legacy-md5/'
HOST='crates/brynja-legacy-md5-std/'
GATES={
    'scripts/checks.sh': ('python3 scripts/md5/check-md5-execution.py',
        'python3 scripts/md5/check-md5-execution-codegen.py',
        'python3 scripts/md5/test-md5-execution-native.py',
        'python3 scripts/md5/test-md5-execution-asan.py'),
    'scripts/tag_gate.sh': ('python3 scripts/md5/check-md5-execution-native.py',),
    'scripts/zeroization/check-zeroization-sanitizer.sh': ('python3 scripts/md5/check-md5-execution-asan.py',),
    'scripts/zeroization/check-zeroization-miri.sh': (
        '    run_miri -p brynja-legacy-md5 --features execution --lib batch::execution::tests',
        '    run_miri -p brynja-legacy-md5 --features execution --lib operational_revalidator_unwind_quarantines_without_instructions',
        '    run_miri -p brynja-legacy-md5 --features execution --test execution callback_unwind_is_terminal_and_transactional'),
    '.github/workflows/ci.yml': ('  ordinary-md5:',
        '        run: python3 scripts/md5/check-md5-execution-ci.py ${{ matrix.architecture }}'),
}
CHECKS={
    LEAF+'src/cpu/session.rs': (
        'if !backend.is_admitted() && !cfg!(all(feature = "cpu-evidence", brynja_md5_cpu_evidence))',
        'return Err(Md5BackendError::NotAdmitted)',
        'Self::initialize(backend, revalidate, corrupt_kat)',
        'require_architecture(backend)?;', 'session.compress(&mut states, &blocks)?;',
        '.take(backend.lane_width())', 'session.healthy.set(false)',
        'pub unsafe fn from_platform(', 'session.ensure_healthy()?;',
        'PhantomData<*mut ()>', 'target_feature = "avx2"', 'target_feature = "neon"',
        'super::x86_avx2_md5::compress(state, block);', 'super::aarch64_neon_md5::compress(state, block);',
        'if !self.healthy.get() { return Err(Md5BackendError::Quarantined); }',
        'self.healthy.set(false); if !(self.revalidate)(self.backend)',
    ),
    LEAF+'src/batch/execution.rs': (
        'pub struct PublicData(())', 'pub fn with_authority(authority: Authority, mode: Mode)',
        'Caller-asserted classification ONLY, not verified at runtime.',
        'confidentiality or zeroization guarantee and does not declassify secrets.',
        'each SIMD compression, and before output commit.',
        'the batch: callbacks can revoke authority between these boundaries.',
        'self.ready()?;', 'if self.required && authority.is_none()',
        'if self.required && work.vector_blocks == 0',
        'vector::execute(&mut owner, inputs, control, a.session())',
        'guard.complete = error != Md5BatchError::Backend;',
        'self.ready()?; if self.required', 'owner.commit_public(output); guard.complete = true;',
        'if !self.complete { self.executor.quarantine(); }',
        'input.is_some_and(|bits| bits.split().0.len() >= 64)',
        'authority.filter(|_| work.vector_blocks != 0)',
    ),
    HOST+'src/execution/platform.rs': (
        'target_arch = "x86_64", target_feature = "avx2"',
        'Authority::for_compiled_target()', 'std::arch::is_aarch64_feature_detected!("neon")',
        'target_os = "linux"', 'target_os = "android"', 'target_os = "macos"',
        'target_os = "ios"', 'target_os = "windows"',
        'backend == Md5Backend::Aarch64Neon && availability() == Ok(backend)',
        'Authority::from_platform(backend, revalidate)',
    ),
    HOST+'src/execution/mod.rs': (
        'Err(Error::Unavailable(_)) if mode == Mode::Prefer', 'Err(error) => Err(error)',
    ),
    'scripts/md5/check-md5-execution-asan.py': (
        "env['ASAN_OPTIONS']='detect_leaks=1:halt_on_error=1:exitcode=1'",
        "env['LSAN_OPTIONS']='exitcode=23'",
        "env['RUSTFLAGS']='-Zsanitizer=address -C target-feature=+avx2'",
        "env['BRYNJA_REQUIRE_MD5_EXECUTION']='1'", 'check=True',
    ),
    'scripts/md5/check-md5-execution-ci.py': (
        "BRYNJA_REQUIRE_MD5_EXECUTION='1'", "'--features','execution'",
        "'; cases=2048; normal-build SIMD'", 'host.host(lane)',
    ),
}


def paths(root=ROOT):
    paths=set(CHECKS)
    for crate in ('brynja-core','brynja-hash-core','brynja-legacy-md5','brynja-legacy-md5-std'):
        base=root/'crates'/crate
        paths.add(f'crates/{crate}/Cargo.toml')
        paths.update(p.relative_to(root).as_posix() for p in (base/'src').rglob('*.rs'))
    paths.update((LEAF+'tests/execution.rs',HOST+'tests/execution.rs','docs/legacy-md5-execution.md'))
    paths.update((LEAF+'README.md',HOST+'README.md'))
    paths.update('assurance/md5-execution/'+name for name in ('Cargo.toml','Cargo.lock','src/main.rs'))
    paths.update('scripts/md5/'+name for name in (
        'md5_execution_policy.py','check-md5-execution.py','test-md5-execution.py',
        'execution_package.py','check-md5-package.py','check-md5-execution-differential.py',
        'check-md5-execution-asan.py','capture-md5-execution-native.py',
        'md5_execution_native.py','check-md5-execution-native.py',
        'check-md5-execution-ci.py','check-md5-execution-codegen.py','test-md5-execution-native.py',
        'test-md5-execution-asan.py','capture-md5-cpu-native.py',
        'check-md5-differential.py'))
    return sorted(paths)


def read(root,name):
    path=root/name
    if path.is_symlink() or not path.is_file() or path.stat().st_size>2_000_000:
        raise ValueError('invalid MD5 execution source: '+name)
    return path.read_bytes().replace(b'\r\n',b'\n')


def snapshot(root=ROOT):
    return {p:hashlib.sha256(read(root,p)).hexdigest() for p in paths(root)}


def validate(root=ROOT,reviewed=True):
    # Orchestration is checked structurally but is not native execution input;
    # unrelated CI edits must not pretend the algorithm changed or admit a lane.
    for name,lines in GATES.items():
        source=read(root,name).decode().splitlines()
        if not all(source.count(line)==1 for line in lines):
            raise ValueError('MD5 execution gate coverage removed: '+name)
    for name,tokens in CHECKS.items():
        source=re.sub(r'\s+','',read(root,name).decode())
        for token in tokens:
            if re.sub(r'\s+','',token) not in source: raise ValueError('MD5 execution boundary lost: '+token)
    session=read(root,LEAF+'src/cpu/session.rs').decode()
    if re.search(r'pub(?:\([^)]*\))?\s+fn\s+(initialize|construct|session)\(',session.replace('pub(crate) fn session(', 'fn session(')):
        raise ValueError('internal session construction/export became public')
    for name in (LEAF+'src/batch/execution.rs',HOST+'src/execution/mod.rs'):
        text=read(root,name).decode()
        if re.search(r'\bunsafe\b|\.(unwrap|expect)\(|\b(panic|unimplemented)!',text):
            raise ValueError('unreviewed safe execution escape')
    leaf=tomllib.loads(read(root,LEAF+'Cargo.toml').decode())
    host=tomllib.loads(read(root,HOST+'Cargo.toml').decode())
    if leaf['features']['default'] or leaf['features'].get('execution')!=['cpu']:
        raise ValueError('ordinary execution must be default-off')
    old_features={'default':[],'runtime-execution':['brynja-legacy-md5/execution']}
    hardened_features={**old_features,'runtime-hardened-execution':['brynja-legacy-md5/hardened-execution']}
    strict_features={**hardened_features,'strict-execution':['dep:brynja-core', 'dep:brynja-crypto-cpu-std', 'brynja-crypto-cpu-std/protected-memory']}
    compiled_features={**strict_features,'strict-acceleration':['strict-execution', 'brynja-legacy-md5/hardened-execution']}
    if host['features'] not in (old_features, hardened_features, strict_features, compiled_features):
        raise ValueError('hosted execution must be separately default-off')
    for name in paths(root):
        if name.endswith(('.rs','.py')) and len(read(root,name).splitlines())>500:
            raise ValueError('MD5 execution source exceeds review bound')
    if reviewed and json.loads(read(root,REVIEW))!={'schema':1,'sha256':snapshot(root)}:
        raise ValueError('MD5 execution reviewed source changed')


def write():
    validate(reviewed=False)
    (ROOT/REVIEW).write_text(json.dumps({'schema':1,'sha256':snapshot()},indent=2)+'\n')
