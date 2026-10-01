#!/usr/bin/env python3
"""Build private sequential AVX2 batch component, not multi-message SIMD/VBS proof."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import windows_enclave_sha3_accelerated_build as base
import windows_enclave_sha3_batch_oracle as oracle

ROOT, SOURCE = base.ROOT, base.SOURCE
FILES = ('sha3_batch_accelerated.rs', 'sha3_batch_accelerated_authority_tests.rs', 'sha3_batch_accelerated_wire.rs')


def build(directory, target):
    base.build(directory, target)
    record = json.loads((directory/'sha3-accelerated-build.json').read_text())
    common = record['commands'][-1][:record['commands'][-1].index('--crate-name')]
    paths = {Path(__file__).resolve(), Path(oracle.__file__).resolve(), SOURCE/'sha3_batch_tests.rs'}
    for name in FILES:
        shutil.copyfile(SOURCE/name, directory/name)
        paths.add(SOURCE/name)
    # Preserve scalar tests and their scalar reference; change only authority
    # construction/lifetimes. The returning helper borrows its caller's owner.
    tests = (SOURCE/'sha3_batch_tests.rs').read_text()
    if tests.count('let mut o = Owner::new();') != 19 or tests.count('let mut o = retained();') != 7:
        raise ValueError('Batch test adaptation anchors changed')
    tests = tests.replace('fn retained() -> Owner {\n    let mut o = Owner::new();',
        "fn retained(authority: &Authority) -> Owner<'_> {\n    let mut o = Owner::new(authority).unwrap();")
    tests = tests.replace('let mut o = Owner::new();', 'let authority = make_authority(); let mut o = Owner::new(&authority).unwrap();')
    tests = tests.replace('let mut o = retained();', 'let authority = make_authority(); let mut o = retained(&authority);')
    tests = tests.replace('&Owner)', "&Owner<'_>)").replace('&mut Owner,', "&mut Owner<'_>,")
    tests = tests.replace('State::new(Algorithm::decode(s.identity)', 'reference::State::new(Algorithm::decode(s.identity)')
    tests += '\n#[allow(dead_code)] #[path = "sha3_stream_state.rs"] mod reference;\n'
    tests += 'struct Scratch([u8; 1024]); impl Drop for Scratch { fn drop(&mut self) { let _ = clear_owned_region(&mut self.0); } }\n'
    tests += 'fn make_authority() -> Authority { Authority::new(Kernel::X86Keccak).unwrap() }\n'
    (directory/'sha3_batch_accelerated_tests.rs').write_text(tests)
    paths.add(SOURCE/'sha3_batch_wire_tests.rs')
    wire = (SOURCE/'sha3_batch_wire_tests.rs').read_text()
    if wire.count('let (mut o, n) = retained();') != 3 or wire.count('let mut o = Owner::new();') != 2:
        raise ValueError('Batch wire test adaptation anchors changed')
    wire = wire.replace('sha3_batch_wire', 'sha3_batch_accelerated_wire')
    wire = wire.replace('let mut words = [0_u64; 36];', 'let mut words = [0_u64; 38]; words[36] = 1;')
    wire = wire.replace('words[12..]', 'words[12..36]').replace('changed[96..].fill(0)', 'changed[96..288].fill(0)')
    wire = wire.replace('fn retained() -> (Owner, u64) {\n    let mut o = Owner::new();',
        "fn retained(authority: &Authority) -> (Owner<'_>, u64) {\n    let mut o = Owner::new(authority).unwrap();")
    wire = wire.replace('let (mut o, n) = retained();', 'let authority = make_authority(); let (mut o, n) = retained(&authority);')
    wire = wire.replace('let mut o = Owner::new();', 'let authority = make_authority(); let mut o = Owner::new(&authority).unwrap();')
    wire = wire.replace('&mut Owner,', "&mut Owner<'_>,").replace('&Owner)', "&Owner<'_>)")
    wire = wire.replace('let mut reference = State::new(', 'let mut reference = reference::State::new(')
    wire = wire.replace('(7, 1)]', '(7, 1), (36, 0), (37, 1)]')
    wire += '\n#[allow(dead_code)] #[path = "sha3_stream_state.rs"] mod reference;\n'
    wire += 'struct Scratch([u8; 1024]); impl Drop for Scratch { fn drop(&mut self) { let _ = clear_owned_region(&mut self.0); } }\n'
    wire += 'fn make_authority() -> Authority { Authority::new(Kernel::X86Keccak).unwrap() }\n'
    (directory/'sha3_batch_accelerated_wire_tests.rs').write_text(wire)
    count = oracle.generate(directory/'sha3-batch-oracle.txt')
    paths.update(ROOT/p for p in ('scripts/sha3/check-cshake-differential.py',
        'scripts/sha3/check-sha3-bit-differential.py',
        'crates/brynja-hash-sha3/tests/vectors/nist-bit-selected.txt'))
    deps = [part for name in ('brynja_core', 'brynja_crypto_cpu', 'brynja_hash_sha3',
                             'sha3_stream', 'sha3_accelerated_state')
        for part in ('--extern', name+'='+str(directory/('lib'+name+'.rlib')))]
    entry = str(directory/'sha3_batch_accelerated.rs')
    library = common+['--crate-name', 'sha3_batch_accelerated', '--crate-type', 'rlib', entry,
                     '-o', str(directory/'libsha3_batch_accelerated.rlib')]+deps
    base.run(library)
    binary = directory/('batch-accelerated-test.exe' if 'windows' in target else 'batch-accelerated-test')
    command = common+['--crate-name', 'sha3_batch_accelerated', '--test', entry, '-o', str(binary)]+deps
    base.run(command)
    record['commands'] += [library, command]
    record['source_sha256'].update({p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    record.update(status='SEQUENTIAL_AVX2_BATCH_COMPONENT_BUILD_ONLY', oracle_cases=count,
        multi_message_simd=False, test_adaptation='Scalar batch tests: authority construction/lifetimes only; scalar reference preserved')
    record['generated_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in directory.iterdir() if p.suffix in ('.rs', '.txt')}
    (directory/'sha3-batch-accelerated-build.json').write_text(json.dumps(record, indent=2)+'\n')
    return command, binary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    build(args.directory.resolve(), target)
