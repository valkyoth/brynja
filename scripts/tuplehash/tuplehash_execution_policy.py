"""TupleHash execution source and verification closure, distinct from portable TupleHash."""
import hashlib
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[2]
CRATE = 'crates/brynja-hash-tuple'
SOURCE = CRATE + '/src/execution/'
REVIEW = 'security/tuplehash-execution-reviewed.json'
FILES = ('mod.rs', 'backend.rs', 'core_state.rs', 'common.rs', 'item.rs', 'fixed.rs',
         'output.rs', 'xof.rs', 'ownership.rs', 'core_state/tests.rs')
TOKENS = {
    'mod.rs': ('pub trait HardenedState: sealed::State', 'Require(Option<KeccakSession',
               'Prefer(Option<KeccakSession', 'impl HardenedState for HardenedReader'),
    'backend.rs': ('Mode::Require(None) => return Err(Error::AccelerationUnavailable)',
        'Mode::Prefer(Some(session)) | Mode::Require(Some(session)) => Some(session)',
        'Portable128(HardenedCshake128)', 'Portable256(HardenedCshake256)',
        'Accelerated128(accelerated::Cshake128', 'Accelerated256(accelerated::Cshake256',
        'Self::Portable128(s) => s.wipe_in_place()', 'Self::Portable256(s) => s.wipe_in_place()',
        'Self::Accelerated128(s) => s.cancel()', 'Self::Accelerated256(s) => s.cancel()', 'b"TupleHash"'),
    'core_state.rs': ('state: State<', 'metadata: Metadata', 'Operation::new(self)',
        'if !self.completed {', 'self.core.cancel();', 'self.state.wipe();',
        'self.metadata.wipe();', 'SecretEncodedInteger::left(bits)', 'SecretEncodedInteger::right(bits)',
        'core.phase(1)?;', 'core.phase(2)?;', 'core.phase(3)?;', 'core.state.update(&[])?;',
        'checked_remaining_after(', '.checked_add(prefix_bits)', '.checked_add(count)',
        '.item_count()', '.checked_add(1)', '.checked_add(bits)', 'let _ = clear_owned_region(bytes);',
        'Ok(TupleHashSecretOutput::new(output))', 'for chunk in input.chunks(168)',
        'self.metadata.staging.iter_mut()', 'clear_owned_region(&mut self.metadata.staging)'),
    'common.rs': ('pub fn push_item_bits(', 'self.core.begin(length)?;',
        'self.core.fragment(item)?;', 'self.core.complete()', 'pub fn begin_item(',
        'self.core.begin(bits)?;', 'pub fn cancel(&mut self)'),
    'item.rs': ("core: &'s mut Core<'a>", 'complete: bool', 'pub fn finish(mut self)',
        'self.core.complete()?;', 'if !self.complete {', 'self.core.cancel();'),
    'fixed.rs': ('pub fn finalize(mut self', 'pub fn finalize_secret(',
        'mut self,', 'output::fixed_secret(&mut self.core', 'output::fixed_public(',
        'TupleHashPublicDeclassification', 'pub fn finalize_bits('),
    'xof.rs': ("core: &'s mut Core<'a>", 'impl Drop for $name', 'self.core.cancel();',
        'pub fn finalize_xof(&mut self)', 'core: &mut self.core', 'self.core.finish(0)?;',
        'TupleHashPublicDeclassification', 'self.core.secret(', 'self.core.public('),
    'output.rs': ('clear_owned_region(&mut self.0)', 'clear_owned_region(self.0)',
        'clear_owned_region(bytes)', '.checked_mul(8)', 'core.finish(bits)?;',
        'core: &mut Core', 'core.public(bytes, valid, stage.0, true)',
        'core.secret(bytes, valid, true)'),
}
REGIONS = {'pending': 1, 'used': 1, 'items': 16, 'remaining': 16,
           'input_bits': 16, 'output_bits': 16, 'phase': 1, 'staging': 168}
DOC_TYPES = tuple(name + "<'static>" for name in (
    'TupleHash128', 'TupleHash256', 'HardenedTupleHash128', 'HardenedTupleHash256',
    'TupleHashXof128', 'TupleHashXof256', 'HardenedTupleHashXof128', 'HardenedTupleHashXof256'
)) + ("Reader<'static, 'static>", "HardenedReader<'static, 'static>", "TupleItemWriter<'static, 'static>")
DOC_CASES = tuple(f'//! ```compile_fail,E0277\n//! fn require<T: {bound}>() {{}}\n'
                 f'//! require::<brynja_hash_tuple::execution::{name}>();\n//! ```'
                 for name in DOC_TYPES for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'))


def require(value, label):
    if not value:
        raise ValueError('TupleHash execution contract: ' + label)


def read(root, name):
    path = root / name
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 4_000_000,
            'regular bounded input: ' + str(name))
    return path.read_text().replace('\r\n', '\n')


def semantic(root):
    for case in DOC_CASES:
        require(case in read(root, SOURCE + 'ownership.rs'), 'public owner rustdoc invariant')
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
        'default': [],
        'hardened-execution': ['brynja-hash-sha3/hardened-execution'],
        'runtime-execution': ['hardened-execution', 'brynja-hash-sha3/runtime-execution'],
    }, 'exact default-off feature graph')
    require(manifest['dependencies'] == {'brynja-core': {'workspace': True},
        'brynja-hash-sha3': {'workspace': True}}, 'first-party dependency closure')
    require('#[cfg(feature = "hardened-execution")]\npub mod execution;' in
            read(root, CRATE + '/src/lib.rs'), 'default-off module')


def validate(root=ROOT, write=False):
    semantic(root)
    require('python3 scripts/tuplehash/check-tuplehash-execution-native.py' in
            read(root, 'scripts/tag_gate.sh').splitlines(), 'native release blocker')
    for command in ('run_miri -p brynja-hash-tuple --features hardened-execution --lib execution',
                    'run_miri -p brynja-hash-tuple --features hardened-execution --test execution'):
        require(command in [line.strip() for line in read(root, 'scripts/zeroization/check-zeroization-miri.sh').splitlines()],
                'affected TupleHash Miri execution')
    require('python3 scripts/tuplehash/check-tuplehash-execution.py --asan' in
            read(root, 'scripts/zeroization/check-zeroization-sanitizer.sh').splitlines(), 'native ASan command')
    for command in (
        'python3 scripts/tuplehash/check-tuplehash-execution.py',
        'python3 scripts/tuplehash/check-tuplehash-execution-package.py',
        'python3 scripts/tuplehash/check-tuplehash-execution-codegen.py',
        'python3 scripts/tuplehash/test-tuplehash-execution-policy.py',
        'cargo clippy --locked --offline --manifest-path assurance/tuplehash-execution/Cargo.toml --all-targets -- -D warnings',
    ):
        require(command in read(root, 'scripts/checks.sh').splitlines(), 'mandatory command ' + command)
    paths = set()
    for package in (CRATE, 'crates/brynja-core', 'crates/brynja-hash-core',
                    'crates/brynja-hash-sha3', 'crates/brynja-crypto-cpu'):
        paths.add(package + '/Cargo.toml')
        paths.update(p.relative_to(root).as_posix() for p in (root / package / 'src').rglob('*.rs'))
    paths.update(p.relative_to(root).as_posix() for p in (root / CRATE / 'tests').rglob('*.rs'))
    paths.update(p.relative_to(root).as_posix() for p in (root / 'assurance/tuplehash-execution').rglob('*')
                 if p.is_file() and 'target' not in p.parts)
    paths.update(p.relative_to(root).as_posix() for p in (root / 'scripts/tuplehash').glob('*execution*.py'))
    paths.update(('scripts/checks.sh', 'scripts/tag_gate.sh', 'scripts/zeroization/check-zeroization-miri.sh',
                  'scripts/zeroization/check-zeroization-sanitizer.sh', 'docs/tuplehash-accelerated-execution.md'))
    paths.update(('scripts/tuplehash/check-tuplehash-differential.py', 'scripts/sha3/check-cshake-differential.py',
                  'scripts/sha3/check-sha3-bit-differential.py', 'scripts/cryptography/mir_cleanup_flow.py'))
    record = {'version': '0.24.39', 'status': 'implementation-review; native-qualification-pending',
        'regions': REGIONS, 'sha256': {p: hashlib.sha256(read(root, p).encode()).hexdigest() for p in sorted(paths)}}
    if write:
        (root / REVIEW).write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    require(json.loads(read(root, REVIEW)) == record, 'source drift; reopen review')
