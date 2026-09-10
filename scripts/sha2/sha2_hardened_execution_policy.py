"""Reviewed source-owned regions and default-off hardened execution boundary."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
REVIEW = Path('security/sha2-hardened-execution-reviewed.json')
CPU = 'crates/brynja-crypto-cpu'
HASH = 'crates/brynja-hash-sha2'
REGIONS = {
    f'{CPU}/src/hardened_execution/scratch.rs#Scratch': ['schedule:640', 'vectors:64'],
    f'{HASH}/src/hardened/owner.rs#HardenedSha2Owner': [
        'chaining_state:64', 'partial_input:128', 'message_length:16', 'phase:2',
        'message_schedule:640', 'block_copy:128', 'padding_block:128', 'output_staging:64'],
}


def read(root, path):
    source = root / path
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('invalid hardened execution source: ' + str(path))
    return source.read_text().replace('\r\n', '\n')


def require(condition, message):
    if not condition:
        raise ValueError('hardened execution policy: ' + message)


def validate(root=ROOT, write=False):
    for owner, regions in REGIONS.items():
        path, identity = owner.split('#')
        source = read(root, path)
        require(f'impl Drop for {identity}' in source and 'self.wipe();' in source, 'owner Drop')
        for region in regions:
            name, size = region.split(':')
            require(f'{name}: [u8; {size}]' in source, 'exact region ' + region)
            require(f'clear_owned_region(&mut self.{name})' in source, 'complete clearing ' + name)
    cpu = read(root, f'{CPU}/src/hardened_execution/mod.rs')
    require('if !session.known_answer(kernel)?' in cpu, 'real hardened KAT')
    require('self.check(wide)?;' in cpu and 'self.route.check()?' in cpu, 'health and identity')
    require('impl Drop for Operation' in cpu and 'self.scratch.wipe();' in cpu, 'operation cleanup')
    require('if !self.completed' in cpu and 'self.route.quarantine();' in cpu, 'unwind quarantine')
    engine = read(root, f'{HASH}/src/hardened_execution/engine.rs')
    require('impl Drop for Update' in engine and 'self.owner.wipe();' in engine and '*self.failed = true;' in engine, 'mutable update unwind cleanup')
    for path in (f'{HASH}/src/hardened_execution/general.rs', f'{HASH}/src/hardened_execution/named.rs'):
        source = read(root, path)
        require('let guard = begin(destination,' in source and 'mut self,' in source, 'consuming secret outputs')
        require('PublicDeclassification' in source and 'sealed::Registered' in source, 'sealed classification')
        require('Sha512TDigest::from_bytes' not in source, 'no public secret import')
    for name in (CPU, HASH):
        library = read(root, f'{name}/src/lib.rs')
        require('#[cfg(feature = "hardened-execution")]\npub mod hardened_execution;' in library, 'default-off module')
    driver = read(root, 'scripts/checks.sh').splitlines()
    for name in ('check-sha2-hardened-execution.py', 'check-sha2-hardened-execution-codegen.py', 'test-sha2-hardened-execution.py'):
        require('python3 scripts/sha2/' + name in driver, 'repository gate ' + name)
    miri = read(root, 'scripts/zeroization/check-zeroization-miri.sh')
    require('--lib hardened_execution::engine::tests' in miri and '--lib hardened_execution::tests::output_owner_clears_during_recoverable_unwind' in miri, 'Miri lifecycle')
    require('-p brynja-crypto-cpu --features hardened-execution --lib hardened_execution' in miri, 'Miri scratch')
    require('--all-features --lib hardened_execution' in read(root, 'scripts/zeroization/check-zeroization-sanitizer.sh'), 'ASan scope')
    require('\npython3 scripts/sha2/check-sha2-hardened-asan.py\n' in
            read(root, 'scripts/zeroization/check-zeroization-sanitizer.sh'), 'native ASan gate')
    require("FLAGS = '-Zsanitizer=address -C target-feature=+sha,+sse2'" in
            read(root, 'scripts/sha2/hardened_native_host.py'), 'ASan actual kernel flags')
    require('python3 scripts/release/run-verification.py plan --check\n'
            'python3 scripts/sha2/check-sha2-hardened-native-evidence.py\nverify() {' in
            read(root, 'scripts/tag_gate.sh'), 'mandatory pre-tag native evidence')
    require('python3 scripts/sha2/test-sha2-hardened-native.py' in driver, 'native gate regressions')
    paths = set()
    for directory in (CPU + '/src', HASH + '/src', 'assurance/sha2-hardened-execution/src'):
        for path in (root / directory).rglob('*.rs'):
            relative = path.relative_to(root)
            source = read(root, relative)
            require(len(source.splitlines()) <= 500, 'source size ' + str(relative))
            paths.add(relative)
    for name in (CPU + '/Cargo.toml', HASH + '/Cargo.toml', 'package-policy.toml',
                 'assurance/sha2-hardened-execution/Cargo.toml', 'assurance/sha2-hardened-execution/Cargo.lock',
                 'scripts/checks.sh', 'scripts/zeroization/check-zeroization-miri.sh',
                 'scripts/zeroization/check-zeroization-sanitizer.sh',
                 'scripts/sha2/check-sha2-execution.py', 'docs/sha2-hardened-execution.md'):
        paths.add(Path(name))
    paths.update(path.relative_to(root) for path in (root / 'scripts/sha2').glob('*hardened-execution*.py'))
    paths.add(Path('scripts/sha2/sha2_hardened_execution_policy.py'))
    paths.add(Path('scripts/sha2/sha2_hardened_cleanup_mutants.py'))
    for name in ('scripts/tag_gate.sh', 'scripts/sha2/hardened_native_host.py',
                 'scripts/sha2/hardened_native_evidence.py', 'scripts/sha2/check-sha2-hardened-asan.py',
                 'scripts/sha2/check-sha2-hardened-native-evidence.py',
                 'scripts/sha2/capture-sha2-hardened-native.py', 'scripts/sha2/test-sha2-hardened-native.py'):
        paths.add(Path(name))
    expected = {'version': '0.24.34', 'regions': REGIONS,
                'residuals': ['registers', 'compiler-copies', 'spills', 'caches', 'swap', 'dumps', 'abort', 'forget', 'caller-copies'],
                'sha256': {str(path).replace('\\', '/'): hashlib.sha256(read(root, path).encode()).hexdigest() for path in sorted(paths)}}
    if write:
        (root / REVIEW).write_text(json.dumps(expected, indent=2, sort_keys=True) + '\n')
    require(json.loads(read(root, REVIEW)) == expected, 'source changed; reopen review')


def regressions():
    import shutil
    import tempfile
    with tempfile.TemporaryDirectory(prefix='brynja-hardened-policy-') as temporary:
        root = Path(temporary)
        # Copy exactly the registered trusted source closure, not build output.
        review = json.loads(read(ROOT, REVIEW))
        for name in [*review['sha256'], str(REVIEW)]:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, path)
        validate(root)
        cases = [(f'{CPU}/src/hardened_execution/scratch.rs', f'clear_owned_region(&mut self.{field})', 'Ok::<(), ()>(())') for field in ('schedule', 'vectors')]
        cases += [(f'{HASH}/src/hardened/owner.rs', f'clear_owned_region(&mut self.{field.split(":")[0]})', 'Ok::<(), ()>(())') for field in list(REGIONS.values())[1]]
        cases += [(f'{CPU}/src/hardened_execution/mod.rs', 'if !session.known_answer(kernel)?', 'if false'),
                  (f'{HASH}/src/hardened_execution/engine.rs', '*self.failed = true;', '*self.failed = false;'),
                  (f'{HASH}/src/lib.rs', '#[cfg(feature = "hardened-execution")]', '#[cfg(feature = "cpu")]'),
                  ('scripts/checks.sh', 'python3 scripts/sha2/check-sha2-hardened-execution-codegen.py', '# removed')]
        cases += [('scripts/tag_gate.sh', 'python3 scripts/sha2/check-sha2-hardened-native-evidence.py', '# omitted'),
                  ('scripts/zeroization/check-zeroization-sanitizer.sh', 'python3 scripts/sha2/check-sha2-hardened-asan.py', '# omitted'),
                  ('scripts/sha2/hardened_native_host.py', '+sha,+sse2', '+sse2')]
        for name, before, after in cases:
            path = root / name
            original = path.read_text()
            require(before in original, 'stale mutation')
            try:
                path.write_text(original.replace(before, after))
                try:
                    validate(root)
                except ValueError:
                    continue
                raise AssertionError('hardened policy mutant escaped: ' + before)
            finally:
                path.write_text(original)
    print(f'Hardened execution region/gate policy rejects {len(cases)} regressions')
