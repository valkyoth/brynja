"""KMAC execution source and verification closure, distinct from portable KMAC."""
import hashlib
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[2]
CRATE = 'crates/brynja-mac-kmac'
SOURCE = CRATE + '/src/execution/'
REVIEW = 'security/kmac-execution-reviewed.json'
FILES = ('mod.rs', 'backend.rs', 'core_state.rs', 'fixed.rs', 'output.rs', 'xof.rs', 'core_state/tests.rs')
TOKENS = {
    'mod.rs': ('pub trait HardenedState: sealed::State', 'Require(Option<KeccakSession', 'Prefer(Option<KeccakSession'),
    'backend.rs': ('Mode::Require(None) => return Err(Error::AccelerationUnavailable)',
                   'Mode::Prefer(Some(session)) | Mode::Require(Some(session)) => Some(session)',
                   'Portable128(HardenedCshake128)', 'Portable256(HardenedCshake256)',
                   'Accelerated128(accelerated::Cshake128', 'Accelerated256(accelerated::Cshake256',
                   'Self::Portable128(s) => s.wipe_in_place()', 'Self::Portable256(s) => s.wipe_in_place()',
                   'Self::Accelerated128(s) => s.cancel()', 'Self::Accelerated256(s) => s.cancel()', 'b"KMAC"'),
    'core_state.rs': ('state: State<', 'metadata: Metadata', 'Operation::new(self)', 'if !self.completed {',
                      'self.core.cancel();', 'self.state.wipe();', 'self.metadata.wipe();',
                      'if !conformance && key_bits < strength', 'absorb_key(&mut core.state',
                      'if xof { 0 } else { bits }', '.checked_add(length)', '.checked_add(bits)',
                      'operation.core.phase(1)?;', 'operation.core.phase(2)?;',
                      'let _ = clear_owned_region(output);', 'Ok(KmacSecretOutput::new(result))'),
    'fixed.rs': ('pub fn finalize_tag(mut self', 'pub fn finalize_secret(', 'mut self,',
                 'fn tag<', '&mut self,', 'fn secret<', 'let _ = clear_owned_region(bytes);',
                 'pub fn verify_exact(', '!= expected_bits', 'output::verify(&mut self.core, candidate)'),
    'xof.rs': ("core: &'s mut Core<'a>", 'impl Drop for Reader', 'self.core.cancel();',
               'pub fn finalize_xof(&mut self)', 'core: &mut self.core', 'KmacPublicDeclassification'),
    'output.rs': ('clear_owned_region(&mut self.0)', 'clear_owned_region(self.0)',
                  'VerificationDifference::new()', 'difference.accumulate(*actual ^ *expected)',
                  'difference.is_zero()', '.checked_mul(8)'),
}
REGIONS = {'message_bytes': 16, 'output_bits': 16, 'phase': 1, 'key_class': 1}
DOC_TYPES = ("Kmac128<'static>", "Kmac256<'static>", "KmacXof128<'static>",
             "KmacXof256<'static>", "Reader<'static, 'static>")
DOC_CASES = tuple(f'//! ```compile_fail,E0277\n//! fn require<T: {bound}>() {{}}\n'
                 f'//! require::<brynja_mac_kmac::execution::{name}>();\n//! ```'
                 for name in DOC_TYPES for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'))
PACKER_TESTS = ('large_final_chunks_keep_bulk_absorption', 'large_partial_keys_keep_bulk_absorption')


def require(value, label):
    if not value:
        raise ValueError('KMAC execution contract: ' + label)


def read(root, name):
    path = root / name
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 4_000_000,
            'regular bounded input: ' + str(name))
    return path.read_text().replace('\r\n', '\n')


def semantic(root):
    for case in DOC_CASES:
        require(case in read(root, SOURCE + 'mod.rs'), 'public owner rustdoc invariant')
    for test in PACKER_TESTS:
        require('fn ' + test + '()' in read(root, CRATE + '/src/packer.rs'), 'bulk absorption regression')
    require({p.relative_to(root / SOURCE).as_posix() for p in (root / SOURCE).rglob('*.rs')} == set(FILES), 'complete source inventory')
    for name in FILES:
        text = read(root, SOURCE + name)
        require(len(text.splitlines()) <= 500, '500-line module budget')
        code = '\n'.join(line.split('//', 1)[0] for line in text.splitlines())
        if name != 'core_state/tests.rs':
            require(not any(token in code for token in (
                'unsafe', 'std::', 'alloc::', 'Vec<', 'Box<', '.unwrap(', '.expect(',
                'panic!', 'static mut', 'Atomic', 'mem::take', 'mem::replace',
                'Sponge', 'execution::Public', 'impl Clone', '#[derive(')), 'forbidden production boundary')
        for token in TOKENS.get(name, ()):
            require(token in code, name + ': ' + token)
    core = read(root, SOURCE + 'core_state.rs')
    for field, width in REGIONS.items():
        require(f'{field}: [u8; {width}]' in core and
                f'clear_owned_region(&mut self.{field})' in core, 'owned region ' + field)
    manifest = tomllib.loads(read(root, CRATE + '/Cargo.toml'))
    require(manifest['features'] == {
        'default': [], 'conformance-testing': [],
        'hardened-execution': ['brynja-hash-sha3/hardened-execution'],
        'runtime-execution': ['hardened-execution', 'brynja-hash-sha3/runtime-execution'],
    }, 'exact default-off feature graph')
    require(manifest['dependencies'] == {'brynja-core': {'workspace': True},
        'brynja-hash-sha3': {'workspace': True}}, 'first-party dependency closure')
    require('#[cfg(feature = "hardened-execution")]\npub mod execution;' in
            read(root, CRATE + '/src/lib.rs'), 'default-off module')


def validate(root=ROOT, write=False):
    semantic(root)
    require('python3 scripts/kmac/check-kmac-execution-native.py' in
            read(root, 'scripts/tag_gate.sh').splitlines(), 'native release blocker')
    for command in ('run_miri -p brynja-mac-kmac --features hardened-execution --lib execution',
                    'run_miri -p brynja-mac-kmac --features hardened-execution --test execution'):
        require(command in [line.strip() for line in read(root, 'scripts/zeroization/check-zeroization-miri.sh').splitlines()],
                'affected KMAC Miri execution')
    require('python3 scripts/kmac/check-kmac-execution.py --asan' in
            read(root, 'scripts/zeroization/check-zeroization-sanitizer.sh').splitlines(), 'native ASan command')
    for command in (
        'python3 scripts/kmac/check-kmac-execution.py',
        'python3 scripts/kmac/check-kmac-execution-package.py',
        'python3 scripts/kmac/check-kmac-execution-codegen.py',
        'python3 scripts/kmac/test-kmac-execution-policy.py',
        'cargo clippy --locked --offline --manifest-path assurance/kmac-execution/Cargo.toml --all-targets -- -D warnings',
    ):
        require(command in read(root, 'scripts/checks.sh').splitlines(), 'mandatory command ' + command)
    paths = set()
    for package in (CRATE, 'crates/brynja-core', 'crates/brynja-hash-core',
                    'crates/brynja-hash-sha3', 'crates/brynja-crypto-cpu'):
        paths.add(package + '/Cargo.toml')
        paths.update(p.relative_to(root).as_posix() for p in (root / package / 'src').rglob('*.rs'))
    paths.update(p.relative_to(root).as_posix() for p in (root / CRATE / 'tests').rglob('*.rs'))
    paths.update(p.relative_to(root).as_posix() for p in (root / 'assurance/kmac-execution').rglob('*')
                 if p.is_file() and 'target' not in p.parts)
    paths.update(p.relative_to(root).as_posix() for p in (root / 'scripts/kmac').glob('*execution*.py'))
    paths.update(('scripts/checks.sh', 'scripts/tag_gate.sh', 'scripts/zeroization/check-zeroization-miri.sh',
                  'scripts/zeroization/check-zeroization-sanitizer.sh', 'docs/kmac-accelerated-execution.md'))
    paths.update(('scripts/kmac/check-kmac-differential.py', 'scripts/sha3/check-cshake-differential.py',
                  'scripts/sha3/check-sha3-bit-differential.py', 'scripts/cryptography/mir_cleanup_flow.py'))
    record = {'version': '0.24.38', 'status': 'implementation-review; native-qualification-pending',
        'regions': REGIONS, 'sha256': {p: hashlib.sha256(read(root, p).encode()).hexdigest() for p in sorted(paths)}}
    if write:
        (root / REVIEW).write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    require(json.loads(read(root, REVIEW)) == record, 'source drift; reopen review')
