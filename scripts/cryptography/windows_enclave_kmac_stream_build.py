#!/usr/bin/env python3
"""Build the isolated KMAC worker component; no enclave/native qualification."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tomllib
import windows_enclave_sha3_stream_build as base

ROOT = base.ROOT
SOURCE = base.SOURCE
run = base.run
FILES = ('kmac_stream.rs', 'kmac_stream_state.rs', 'kmac_stream_tests.rs',
         'kmac_stream_setup.rs', 'kmac_stream_setup_tests.rs')


def oracle_tests():
    path = ROOT / 'scripts/kmac/check-kmac-differential.py'
    spec = importlib.util.spec_from_file_location('kmac_oracle', path)
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    oracle.verify_oracle()
    lines = ['#[test]', 'fn independent_bit_oracle() {']
    count = 0
    for identity, rate, xof in ((1,168,False),(2,136,False),(3,168,True),(4,136,True)):
        for index in range(64):
            key_bits = (256,257,271,511,1024,8191,8192,16385)[index % 8]
            custom_bits = (0,1,7,8,9,135*8+3,16391)[index % 7]
            message_bits = (0,1,7,8,9,rate*8-1,rate*8,rate*8+1)[index % 8]
            output_bits = (256,257,511,512,rate*8+3)[index % 5]
            if xof and index % 11 == 0:
                output_bits = 0
            key = oracle.oracle.canonical(0x100000+index,key_bits)
            custom = oracle.oracle.canonical(0x200000+index,custom_bits)
            message = oracle.oracle.canonical(0x300000+index,message_bits)
            expected = oracle.kmac(rate, oracle.oracle.byte_bits(key)[:key_bits],
                oracle.oracle.byte_bits(message)[:message_bits],
                oracle.oracle.byte_bits(custom)[:custom_bits], output_bits, xof)
            def array(value): return '&['+','.join(map(str,value))+']'
            def last(bits): return ((bits-1)%8+1) if bits else 0
            lines.append(f'check_case({identity}, {array(key)}, {last(key_bits)}, '
                f'{array(custom)}, {last(custom_bits)}, {array(message)}, '
                f'{last(message_bits)}, {array(expected)}, {last(output_bits)});')
            count += 1
    lines.append('}')
    return '\n'.join(lines)+'\n', count


def build(directory, target, testing=False):
    directory = directory.resolve()
    # Reuse the exact default-off SHA-3 dependency builder. Its standalone SHA-3
    # component is not linked into the KMAC test product.
    base.build(directory,target,testing=testing)
    crate = ROOT / 'crates/brynja-mac-kmac'
    policy = tomllib.loads((crate/'Cargo.toml').read_text())
    if policy.get('features',{}).get('default') or policy.get('build-dependencies') or policy['package'].get('build'):
        raise ValueError('unexpected KMAC build graph')
    if policy['dependencies'] != {'brynja-core': {'workspace': True},
                                  'brynja-hash-sha3': {'workspace': True}}:
        raise ValueError('unexpected KMAC dependencies')
    common = ['rustc','+1.98.1','--edition=2024','--target',target,'-D','warnings',
        '-C','opt-level=2','-C','overflow-checks=yes','-C','panic='+('unwind' if testing else 'abort'),
        '-L','dependency='+str(directory)]
    deps = ['--extern','brynja_core='+str(directory/'libbrynja_core.rlib'),
        '--extern','brynja_hash_sha3='+str(directory/'libbrynja_hash_sha3.rlib')]
    command=common+deps+['--crate-name','brynja_mac_kmac','--crate-type','rlib',
        str(crate/'src/lib.rs'),'-o',str(directory/'libbrynja_mac_kmac.rlib')]
    run(command)
    for name in FILES: shutil.copyfile(SOURCE/name,directory/name)
    generated,count=oracle_tests()
    tests=directory/'kmac_stream_tests.rs'
    tests.write_text(tests.read_text()+'\n'+generated)
    artifact=directory/('kmac-tests.exe' if 'windows' in target else 'kmac-tests') if testing else directory/'libkmac_stream.rlib'
    worker=common+['--extern','brynja_core='+str(directory/'libbrynja_core.rlib'),
        '--extern','brynja_mac_kmac='+str(directory/'libbrynja_mac_kmac.rlib'),
        '--crate-name','kmac_stream',str(directory/'kmac_stream.rs')]
    worker += ['--test'] if testing else ['--crate-type','rlib']
    worker += ['-o',str(artifact)]
    run(worker)
    inputs=[Path(__file__),*(SOURCE/name for name in FILES),crate/'Cargo.toml',
        *sorted((crate/'src').rglob('*.rs'))]
    inputs += [ROOT/name for name in ('scripts/kmac/check-kmac-differential.py',
        'scripts/sha3/check-cshake-differential.py', 'scripts/sha3/check-sha3-bit-differential.py')]
    hashes=json.loads((directory/'sha3-stream-build.json').read_text())['source_sha256']
    hashes.update({str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs})
    record=dict(schema=1,status='COMPONENT_BUILD_ONLY',production_qualified=False,target=target,
        oracle_cases=count,commands=[command,worker],source_sha256=hashes,
        artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        generated_tests_sha256=hashlib.sha256(tests.read_bytes()).hexdigest())
    (directory/'kmac-stream-build.json').write_text(json.dumps(record,indent=2)+'\n')
    return artifact


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--target',default='x86_64-pc-windows-msvc')
    parser.add_argument('--test',action='store_true')
    args=parser.parse_args()
    print(build(args.directory,args.target,args.test))
