#!/usr/bin/env python3
"""Build private accelerated TupleHash component, not an enclave qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import windows_enclave_sha3_accelerated_build as base
import windows_enclave_tuple_stream_build as scalar

ROOT, SOURCE = base.ROOT, base.SOURCE
FILES = ('tuple_accelerated.rs', 'tuple_accelerated_state.rs',
         'tuple_accelerated_packer.rs', 'tuple_accelerated_authority_tests.rs')


def build(directory, target):
    base.build(directory, target)
    record = json.loads((directory/'sha3-accelerated-build.json').read_text())
    common = record['commands'][-1][:record['commands'][-1].index('--crate-name')]
    paths = {Path(__file__).resolve(), Path(scalar.__file__).resolve(),
             SOURCE/'tuple_stream_tests.rs', SOURCE/'tuple_stream_state.rs'}
    for name in FILES:
        shutil.copyfile(SOURCE/name, directory/name)
        paths.add(SOURCE/name)
    # Keep the actual scalar bit-packer byte-for-byte, apart from the borrowed
    # state lifetime. Any later framing change requires an explicit reconciliation.
    anchor = 'pub(super) struct Packer'
    packer = (SOURCE/'tuple_accelerated_packer.rs').read_text().split(anchor, 1)[1]
    original = (SOURCE/'tuple_stream_state.rs').read_text().split(anchor, 1)[1]
    if packer.replace("&mut State<'_>", '&mut State') != original:
        raise ValueError('TupleHash scalar/accelerated packer drift')
    tests = (SOURCE/'tuple_stream_tests.rs').read_text()
    if tests.count('Owner::new()') != 14:
        raise ValueError('TupleHash owner test construction changed')
    tests = tests.replace('Owner::new()', 'Owner::new(&authority).unwrap()')
    for name, count in (('o', 12), ('reference', 1), ('expected', 1)):
        before = 'let mut '+name+' = Owner::new(&authority).unwrap();'
        if tests.count(before) != count:
            raise ValueError('TupleHash owner adaptation changed: '+name)
        tests = tests.replace(before, 'let authority = make_authority(); '+before)
    tests = tests.replace('&mut Owner,', "&mut Owner<'_>,").replace('&Owner)', "&Owner<'_>)")
    generated, count = scalar.oracle_tests()
    lines = generated.splitlines()
    wire = [line for line in lines if line.startswith('super::tuple_stream_wire_tests::check_case')]
    if len(wire) != count:
        raise ValueError('TupleHash independent oracle generation changed')
    generated = '\n'.join(line for line in lines if line not in wire)
    tests += '\n'+generated+'\n'
    tests += 'fn make_authority() -> Authority { Authority::new(Kernel::X86Keccak).unwrap() }\n'
    (directory/'tuple_accelerated_tests.rs').write_text(tests)
    for name in ('scripts/tuplehash/check-tuplehash-differential.py',
                 'scripts/sha3/check-cshake-differential.py',
                 'scripts/sha3/check-sha3-bit-differential.py'):
        paths.add(ROOT/name)
    deps = [part for name in ('brynja_core', 'brynja_crypto_cpu', 'brynja_hash_sha3',
                             'sha3_stream', 'sha3_accelerated_state')
            for part in ('--extern', name+'='+str(directory/('lib'+name+'.rlib')))]
    library = common+['--crate-name', 'tuple_accelerated', '--crate-type', 'rlib',
        str(directory/'tuple_accelerated.rs'), '-o', str(directory/'libtuple_accelerated.rlib')]+deps
    base.run(library)
    artifact = directory/('tuple-accelerated-test.exe' if 'windows' in target else 'tuple-accelerated-test')
    command = common+['--crate-name', 'tuple_accelerated', '--test',
        str(directory/'tuple_accelerated.rs'), '-o', str(artifact)]+deps
    base.run(command)
    record['commands'] += [library, command]
    record['source_sha256'].update({p.relative_to(ROOT).as_posix():
        hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    record.update(status='TUPLEHASH_COMPONENT_BUILD_ONLY', oracle_cases=count,
                  test_adaptation='Scalar owner tests with explicit authority/lifetimes; direct oracle cases; wire path remains separate work')
    record['generated_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in directory.glob('*.rs')}
    (directory/'tuple-accelerated-build.json').write_text(json.dumps(record, indent=2)+'\n')
    return command, artifact


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    build(args.directory.resolve(), target)
