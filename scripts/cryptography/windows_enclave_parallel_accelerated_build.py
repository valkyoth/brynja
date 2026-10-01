#!/usr/bin/env python3
"""Build sequential AVX2 ParallelHash author fixture, not enclave qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import windows_enclave_sha3_accelerated_build as base
import windows_enclave_parallel_stream_build as scalar

ROOT, SOURCE = base.ROOT, base.SOURCE
FILES = ('parallel_accelerated.rs', 'parallel_accelerated_state.rs',
         'parallel_accelerated_input.rs', 'parallel_stream_encoding.rs',
         'parallel_accelerated_wire.rs', 'parallel_accelerated_authority_tests.rs')


def adapt(text):
    # Every local owner gets its own live authority; helper-returned owners
    # borrow the caller's authority rather than a temporary or leaked object.
    text = text.replace('fn started(id: u64, block: u64, budget: u64) -> Owner {\n    let mut o = Owner::new();',
        "fn started(authority: &Authority, id: u64, block: u64, budget: u64) -> Owner<'_> {\n    let mut o = Owner::new(authority).unwrap();")
    text = text.replace('fn retained(id: u64) -> Owner {\n    let mut o = started(id, 8, 3);',
        "fn retained(authority: &Authority, id: u64) -> Owner<'_> {\n    let mut o = started(authority, id, 8, 3);")
    text = re.sub(r'let mut (\w+) = Owner::new\(\);',
        r'let authority = make_authority(); let mut \1 = Owner::new(&authority).unwrap();', text)
    text = re.sub(r'let mut (\w+) = (started|retained)\((?!authority)([^;]+)\);',
        r'let authority = make_authority(); let mut \1 = \2(&authority, \3);', text)
    text = text.replace('&Owner,', "&Owner<'_>,")
    return text + '\nfn make_authority() -> Authority { Authority::new(Kernel::X86Keccak).unwrap() }\n'


def build(directory, target):
    base.build(directory, target)
    record = json.loads((directory/'sha3-accelerated-build.json').read_text())
    common = record['commands'][-1][:record['commands'][-1].index('--crate-name')]
    paths = {Path(__file__).resolve(), Path(scalar.__file__).resolve()}
    for name in FILES:
        shutil.copyfile(SOURCE/name, directory/name)
        paths.add(SOURCE/name)
    generated, count, retained, vectors = scalar.oracle_tests()
    (directory/'parallel-vectors.txt').write_text(vectors)
    for src, dst, extra in (
        ('parallel_stream_tests.rs', 'parallel_accelerated_tests.rs', generated),
        ('parallel_retained_tests.rs', 'parallel_accelerated_retained_tests.rs', retained),
        ('parallel_stream_wire_tests.rs', 'parallel_accelerated_wire_tests.rs', ''),
    ):
        paths.add(SOURCE/src)
        tests = adapt((SOURCE/src).read_text())
        if 'wire' in src:
            tests = tests.replace('parallel_stream_wire', 'parallel_accelerated_wire')
            tests = tests.replace('[12,', '[18,').replace('words[0] = 12;', 'words[0] = 18;')
            # Preserve scalar fourteen-word test shapes, append explicit route.
            tests = tests.replace('    out\n}', '    out[112..120].copy_from_slice(&1_u64.to_le_bytes());\n    out\n}')
        (directory/dst).write_text(tests+'\n'+extra)
    for name in ('scripts/parallelhash/check-parallelhash-differential.py',
                 'scripts/sha3/check-cshake-differential.py',
                 'scripts/sha3/check-sha3-bit-differential.py',
                 'crates/brynja-hash-parallel/tests/official_vectors.rs'):
        paths.add(ROOT/name)
    deps = [part for name in ('brynja_core', 'brynja_crypto_cpu', 'brynja_hash_sha3',
                             'sha3_stream', 'sha3_accelerated_state')
            for part in ('--extern', name+'='+str(directory/('lib'+name+'.rlib')))]
    library = common+['--crate-name', 'parallel_accelerated', '--crate-type', 'rlib',
        str(directory/'parallel_accelerated.rs'), '-o', str(directory/'libparallel_accelerated.rlib')]+deps
    base.run(library)
    artifact = directory/('parallel-accelerated-test.exe' if 'windows' in target else 'parallel-accelerated-test')
    command = common+['--crate-name', 'parallel_accelerated', '--test',
        str(directory/'parallel_accelerated.rs'), '-o', str(artifact)]+deps
    base.run(command)
    record['commands'] += [library, command]
    record['source_sha256'].update({p.relative_to(ROOT).as_posix():
        hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    record.update(status='PARALLELHASH_COMPONENT_BUILD_ONLY', oracle_cases=count,
                  test_adaptation='Scalar direct/wire/retained tests with explicit authority lifetimes and version-eighteen route; unchanged independent oracle')
    record['generated_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in directory.glob('*.rs')}
    record['generated_sha256']['parallel-vectors.txt'] = hashlib.sha256((directory/'parallel-vectors.txt').read_bytes()).hexdigest()
    (directory/'parallel-accelerated-build.json').write_text(json.dumps(record, indent=2)+'\n')
    return command, artifact


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    build(args.directory.resolve(), target)
