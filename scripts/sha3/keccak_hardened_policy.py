"""Exact source-owned memory and authority contract for hardened Keccak."""
import hashlib
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[2]
REVIEW = Path('security/keccak-hardened-reviewed.json')
CPU = 'crates/brynja-crypto-cpu'
HASH = 'crates/brynja-hash-sha3'
SCRATCH = CPU + '/src/hardened_execution/keccak_scratch.rs'
ENGINE = HASH + '/src/hardened/accelerated/engine.rs'
REGIONS = {
    SCRATCH: {'lanes': 200, 'columns': 40, 'theta': 40, 'rearranged': 200,
              'current': 32, 'next': 32, 'following': 32},
    ENGINE: {'lanes': 200, 'message_count': 16, 'output_count': 16, 'suffix': 2},
}


def read(root, name):
    path = root / name
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4_000_000:
        raise ValueError('invalid hardened Keccak input: ' + str(name))
    return path.read_text().replace('\r\n', '\n')


def require(value, label):
    if not value:
        raise ValueError('hardened Keccak contract: ' + label)


def semantic(root):
    for name, fields in REGIONS.items():
        source = read(root, name)
        for field, width in fields.items():
            require(f'{field}: [u8; {width}]' in source, 'region width: ' + field)
            require(f'clear_owned_region(&mut self.{field})' in source, 'region clearing: ' + field)
        require('impl Drop for ' in source and 'self.wipe();' in source, 'owner destruction')
    checks = {
        CPU + '/src/hardened_execution/keccak.rs': (
            'session.permute(core::hint::black_box(&mut state))?',
            'if !correct {', 'session.route.quarantine();',
            'self.check()?;', 'self.route.check()?;',
            'dispatch(kernel, guard.scratch)?;', 'self.scratch.wipe();',
            'if !self.completed {', 'self.route.quarantine();'),
        ENGINE: ('self.session.check().map_err(Error::Backend)',
                 'Operation::new(self)', 'impl Drop for Operation',
                 'self.engine.cancel();', '.checked_add(', 'self.failed = true;'),
        HASH + '/src/hardened/accelerated/mod.rs': (
            'pub trait HardenedState: sealed::State', 'impl sealed::State for'),
        HASH + '/src/hardened/accelerated/reader.rs': (
            'clear_owned_region(&mut self.0)', 'clear_owned_region(self.0)',
            'let mut initialization = begin_secret(output)?;',
            'let mut operation = Operation::new(self);',
            'operation.engine.preflight(length)?;', 'output.copy_from_slice(buffer);'),
        HASH + '/src/hardened/accelerated/fixed.rs': (
            'mut self,', 'begin_secret(output)?;', 'finish_secret(initialization)',
            'Sha3PublicDeclassification'),
        HASH + '/src/hardened/accelerated/xof.rs': (
            'enter_squeezing_in_place', 'squeeze_final_bits_secret_in_place',
            'squeeze_final_bits_public_in_place', 'self.engine.cancel();',
            'absorb_cshake_prefix', 'backend_error.unwrap_or(Error::PrefixEncoding)'),
    }
    for name, tokens in checks.items():
        source = read(root, name)
        for token in tokens:
            require(token in source, name + ': ' + token)
    manifest = tomllib.loads(read(root, HASH + '/Cargo.toml'))
    require(manifest['features']['hardened-execution'] ==
            ['static-execution', 'brynja-crypto-cpu/hardened-execution'], 'exact feature closure')
    require(manifest['features']['default'] == [], 'portable default')
    for directory in (CPU + '/src/hardened_execution', HASH + '/src/hardened/accelerated'):
        for path in (root / directory).rglob('*.rs'):
            source = read(root, path.relative_to(root))
            require(len(source.splitlines()) <= 500, 'source size')
            if path.name != 'tests.rs':
                code = '\n'.join(line.split('//')[0] for line in source.splitlines())
                require(not any(token in code for token in (
                    'unsafe ', 'unsafe{', '.unwrap()', '.expect(', 'Vec<', 'Box<',
                    'static mut ', 'transmute', 'Sponge::', 'HardenedFips202Owner::')),
                    'unreviewed unsafe/allocation/panic/ordinary route')


def validate(root=ROOT, write=False):
    semantic(root)
    for name in ('check-keccak-hardened.py', 'check-keccak-hardened-codegen.py',
                 'test-keccak-hardened.py --compiled', 'test-keccak-hardened-native.py'):
        require('python3 scripts/sha3/' + name in read(root, 'scripts/checks.sh').splitlines(), 'mandatory gate ' + name)
    require('\npython3 scripts/sha3/check-keccak-hardened-native.py\n' in
            read(root, 'scripts/tag_gate.sh'), 'native tag gate')
    require('python3 scripts/sha3/check-keccak-hardened-asan.py' in
            read(root, 'scripts/zeroization/check-zeroization-sanitizer.sh').splitlines(), 'native ASan gate')
    require('hardened::accelerated::engine::tests::every_memory_region_is_explicitly_cleared' in
            read(root, 'scripts/zeroization/check-zeroization-miri.sh'), 'Miri owned memory')
    paths = set()
    # Include the complete first-party authority, shared sponge framing and
    # secret-output closure, not only the changed functions.
    for package in (CPU, HASH, 'crates/brynja-core', 'crates/brynja-hash-core'):
        paths.add(Path(package + '/Cargo.toml'))
        paths.update(path.relative_to(root) for path in (root / package / 'src').rglob('*.rs'))
    paths.add(Path(HASH + '/tests/hardened_execution.rs'))
    paths.update(path.relative_to(root) for path in (root / 'scripts/sha3').glob('*keccak-hardened*.py'))
    paths.add(Path('scripts/sha3/keccak_hardened_policy.py'))
    paths.add(Path('scripts/sha3/keccak_hardened_native.py'))
    paths.update(map(Path, ('scripts/checks.sh', 'scripts/tag_gate.sh',
                           'scripts/zeroization/check-zeroization-miri.sh',
                           'scripts/zeroization/check-zeroization-sanitizer.sh')))
    paths.add(Path('docs/hardened-keccak-execution.md'))
    expected = {'version': '0.24.37', 'regions': REGIONS,
                'status': 'implementation-review; native-qualification-pending',
                'sha256': {path.as_posix(): hashlib.sha256(read(root, path).encode()).hexdigest()
                           for path in sorted(paths)}}
    if write:
        (root / REVIEW).write_text(json.dumps(expected, indent=2, sort_keys=True) + '\n')
    require(json.loads(read(root, REVIEW)) == expected, 'source changed; reopen review')
