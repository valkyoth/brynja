#!/usr/bin/env python3
"""Private sequential SHA-NI batch component; not a shipping image or SIMD proof."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import windows_enclave_sha2_accelerated_build as base

ROOT, SOURCE = base.ROOT, base.SOURCE
FILES = ('sha2_batch_accelerated.rs', 'sha2_batch_accelerated_wire.rs',
         'sha2_batch_accelerated_authority_tests.rs')


def run(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    if result.returncode: raise RuntimeError(result.stdout + result.stderr)
    return result.stdout


def build(directory, target):
    original_command = base.build(directory, target)
    record = json.loads((directory/'sha2-accelerated-build.json').read_text())
    common = original_command[:original_command.index('--test')]
    paths = {Path(__file__).resolve(), *(SOURCE/name for name in FILES),
             SOURCE/'sha2_batch_tests.rs', SOURCE/'sha2_batch_wire_tests.rs'}
    for name in FILES: shutil.copyfile(SOURCE/name, directory/name)
    tests = (SOURCE/'sha2_batch_tests.rs').read_text()
    start = tests.index('#[test]\nfn general_t_and_partial_message_bits_match_scalar_reference()')
    end = tests.index('#[test]\nfn incomplete_out_of_order', start)
    # The narrow route rejects general-t; its exact independent bit cases are
    # generated below instead. All other scalar lifecycle assertions are retained.
    tests = tests[:start] + tests[end:]
    if tests.count('let mut o = Owner::new();') != 15 or tests.count('let mut o = retained();') != 7:
        raise ValueError('Scalar batch adaptation anchors changed')
    tests = tests.replace('fn retained() -> Owner {\n    let mut o = Owner::new();',
        "fn retained(a: &Authority) -> Owner<'_> {\n    let mut o = Owner::new(a).unwrap();")
    tests = tests.replace('let mut o = Owner::new();', 'let a = authority(); let mut o = Owner::new(&a).unwrap();')
    tests = tests.replace('let mut o = retained();', 'let a = authority(); let mut o = retained(&a);')
    # Exercise mixed identities with distinct messages at every activity mask.
    tests = tests.replace('use brynja_hash_sha2::sha256;', 'use brynja_hash_sha2::{sha224, sha256};')
    tests = tests.replace('if mask & (1 << i) != 0 { 2 } else { 0 }',
        'if mask & (1 << i) != 0 { 1 + (i as u64 % 2) } else { 0 }')
    tests = tests.replace('assert_eq!(&output[..32], sha256(&[slot as u8; 3]).unwrap().as_bytes());\n                    assert_eq!(&output[32..], [0; 32]);',
        'let expected = if plan[slot] == 1 { sha224(&[slot as u8; 3]).unwrap().as_bytes().to_vec() } '
        'else { sha256(&[slot as u8; 3]).unwrap().as_bytes().to_vec() };'
        ' assert_eq!(&output[..expected.len()], expected); assert!(output[expected.len()..].iter().all(|b| *b == 0));')
    tests += '\nfn authority() -> Authority { Authority::new(Kernel::X86Sha256).unwrap() }\n'
    tests += '\n#[test]\nfn independent_bit_and_hashlib_oracle() {\n'
    path = ROOT/'scripts/sha2/check-sha2-bit-differential.py'; paths.add(path)
    spec = importlib.util.spec_from_file_location('sha2_bit_oracle', path)
    oracle = importlib.util.module_from_spec(spec); spec.loader.exec_module(oracle)
    count = 0
    for identity, name in ((1, 'sha224'), (2, 'sha256')):
        for length in (0, 1, 7, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 1023, 1024, 2049):
            for last in (range(1, 9) if length else (0,)):
                data = bytearray((i*17) % 256 for i in range(length))
                if data: data[-1] &= (255 << (8-last)) & 255
                expected = bytes.fromhex(oracle.digest32(data, max(0, length-1)*8+last, *oracle.CONFIG[name]))
                if last in (0, 8): assert expected == hashlib.new(name, data).digest()
                tests += (f'{{ let mut data: std::vec::Vec<u8> = (0..{length}).map(|i| (i as u8).wrapping_mul(17)).collect();'
                    f' if let Some(byte)=data.last_mut() {{ *byte &= {((255 << (8-last)) & 255) if last else 0}; }}'
                    f' check_case({identity}, &data, {last}, &{list(expected)}); }}\n')
                count += 1
        expected = hashlib.new(name, b'a'*1_000_000).digest()
        tests += f'check_case({identity}, &std::vec![b\'a\';1_000_000], 8, &{list(expected)});\n'
        count += 1
    tests += '}\n'
    (directory/'sha2_batch_accelerated_tests.rs').write_text(tests)
    wire = (SOURCE/'sha2_batch_wire_tests.rs').read_text()
    if wire.count('let mut o = Owner::new();') != 4: raise ValueError('Wire adaptation anchor changed')
    wire = wire.replace('sha2_batch_wire', 'sha2_batch_accelerated_wire')
    wire = wire.replace('[u64; 16]', '[u64; 18]').replace('[u8; 128]', '[u8; 144]').replace('[0; 128]', '[0; 144]')
    wire = wire.replace('let mut words = [0; 16];', 'let mut words = [0; 18]; words[16] = 1;')
    wire = wire.replace('words[8..]', 'words[8..16]').replace('[1, 2, 3, 4, 5, 6, 0x1001, 0x11ff]', '[1, 2, 1, 2, 1, 2, 1, 2]')
    wire = wire.replace('changed[64..].fill(0)', 'changed[64..128].fill(0)')
    wire = wire.replace('(2, 8)]', '(2, 8), (16, 0), (17, 1)]')
    wire = wire.replace('let mut o = Owner::new();', 'let a = authority(); let mut o = Owner::new(&a).unwrap();')
    wire = wire.replace('complete_wire_batch_binds_all_eight_named_and_general_slots', 'complete_wire_batch_binds_all_eight_narrow_slots')
    expected = b''.join(hashlib.new('sha224' if i % 2 == 0 else 'sha256', b'abc').digest().ljust(64, b'\0') for i in range(8))
    wire = wire.replace('let expected = o.output;', f'let expected: [u8; 512] = {list(expected)}; assert_eq!(o.output, expected);')
    wire += '\nfn authority() -> Authority { Authority::new(Kernel::X86Sha256).unwrap() }\n'
    (directory/'sha2_batch_accelerated_wire_tests.rs').write_text(wire)
    deps = [part for name in ('brynja_core', 'brynja_crypto_cpu', 'brynja_hash_sha2', 'sha2_accelerated')
        for part in ('--extern', name+'='+str(directory/('lib'+name+'.rlib')))]
    entry = str(directory/'sha2_batch_accelerated.rs')
    library = common + ['--crate-name', 'sha2_batch_accelerated', '--crate-type', 'rlib', entry,
        '-o', str(directory/'libsha2_batch_accelerated.rlib')] + deps
    run(library)
    binary = directory/('sha2-batch-accelerated-test.exe' if 'windows' in target else 'sha2-batch-accelerated-test')
    command = common + ['--crate-name', 'sha2_batch_accelerated', '--test', entry, '-o', str(binary)] + deps
    run(command)
    record['commands'] += [library, command]
    record['source_sha256'].update({p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    record.update(status='SEQUENTIAL_SHA_NI_BATCH_BUILD_ONLY', oracle_cases=count, enclave_execution=False,
        multi_message_simd=False, test_adaptation='Scalar batch lifecycle tests retained; narrow plan in wire tests; general-t campaign replaced by independent narrow oracle')
    record['generated_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in directory.iterdir() if p.suffix == '.rs'}
    (directory/'sha2-batch-accelerated-build.json').write_text(json.dumps(record, indent=2)+'\n')
    return command, binary


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    args = p.parse_args()
    target = run(['rustc', '+1.98.1', '-vV']).split('host: ')[1].splitlines()[0]
    build(args.directory.resolve(), target)
