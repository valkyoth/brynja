"""Capture actual crate API execution, not the earlier copied private host."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import windows_enclave_parallel_rust_host_build as fixtures

ROOT = fixtures.ROOT
NATIVE_TEST = 'windows_enclave::parallel_concurrent::tests::native::development_parallel_concurrent_host_campaign'
MUTANTS = (
    ('mod.rs', 'self.0.teardown();', 'let _ = &self.0;'),
    ('mod.rs', 'Self::open_with(location, policy, |pin| pin.signature())',
     'Self::open_with(location, policy, |_| Ok(()))'),
    ('mod.rs', 'returned != 1', 'returned != 2'),
    ('callbacks.rs', '!sys::lock(low, 65536, false)', 'false'),
    ('callbacks.rs', 'frame.verified = true;', 'frame.verified = false;'),
)


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    paths = [ROOT/'Cargo.toml',ROOT/'Cargo.lock',ROOT/'rust-toolchain.toml',Path(__file__).resolve()]
    # Bind the actual oracle composition and case generator, not only generated rows.
    paths += [ROOT/name for name in (
        'scripts/cryptography/windows_enclave_parallel_rust_host_build.py',
        'scripts/cryptography/windows_enclave_parallel_scheduler_native.py',
        'scripts/cryptography/windows_enclave_parallel_input_native.py',
        'scripts/parallelhash/check-parallelhash-differential.py',
        'scripts/sha3/check-cshake-differential.py',
        'scripts/sha3/check-sha3-bit-differential.py')]
    for name in ('brynja-core','brynja-hash-core','brynja-crypto-cpu','brynja-hash-sha2',
                 'brynja-hash-sha3','brynja-crypto-cpu-std'):
        path = ROOT/'crates'/name
        paths += [path/'Cargo.toml',*sorted((path/'src').rglob('*.rs'))]
    return {p.relative_to(ROOT).as_posix():digest(p) for p in paths}


def vectors(path):
    model = fixtures.oracle()
    rows = []
    for case in fixtures.cases():
        if case['mode'] != 'normal': continue
        bits,cbits,obits = case['input_bits'],case['custom_bits'],case['output_bits']
        message,custom = model.oracle.canonical(71+bits,bits),model.oracle.canonical(131,cbits)
        expected = model.parallel_hash(168 if case['identity']%2 else 136,
            model.oracle.byte_bits(message)[:bits],case['block'],model.oracle.byte_bits(custom)[:cbits],
            obits,case['identity']>2)
        rows.append(' '.join([str(v) for v in (case['identity'],case['block'],bits,cbits,obits)] +
            [bytes(v).hex() or '-' for v in (message,custom,expected)]))
    if len(rows) != 25: raise ValueError('oracle population changed')
    path.write_text('\n'.join(rows)+'\n')


def capture(image, out):
    if sys.platform != 'win32': raise ValueError('native Windows required')
    out.mkdir(parents=True,exist_ok=False)
    env = os.environ.copy()
    for key in ('RUSTFLAGS','RUSTDOCFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_TARGET'):
        env.pop(key,None)
    vector = out/'vectors.txt'; vectors(vector)
    env['BRYNJA_PARALLEL_CONCURRENT_IMAGE'] = str(image)
    env['BRYNJA_PARALLEL_CONCURRENT_SHA256'] = digest(image)
    env['BRYNJA_PARALLEL_CONCURRENT_VECTORS'] = str(vector)
    before = sources()
    record = dict(schema=1,status='RUNNING',production_qualified=False,production_signed=False,
        whole_image_cleanup_qualified=False,source_sha256=before,image_sha256=digest(image),
        vector_sha256=digest(vector),commands=[],binaries={},mutations=[])
    def run(label,command,expected=0):
        result = subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True,timeout=900)
        logs = {}
        for name in ('stdout','stderr'):
            path = out/(label+'.'+name); path.write_text(getattr(result,name))
            logs[name+'_sha256'] = digest(path)
        record['commands'].append(dict(label=label,command=command,exit_code=result.returncode,**logs))
        (out/'host-results.json').write_text(json.dumps(record,indent=2)+'\n')
        if result.returncode != expected: raise RuntimeError(label+'\n'+result.stdout[-4000:]+result.stderr[-6000:])
        return result.stdout
    record['rustc'] = run('rustc',['rustc','+1.98.1','-vV'])
    def build(label,release=False):
        args = ['cargo','+1.98.1','test','--locked','--offline','-p','brynja-crypto-cpu-std',
            '--features','strict-sha2,strict-sha3-acceleration','--lib','--no-run','--message-format=json']
        if release: args += ['--release']
        output = run('build-'+label,args)
        artifacts = [json.loads(line) for line in output.splitlines() if line.startswith('{')]
        binaries = [Path(r['executable']) for r in artifacts if r.get('reason')=='compiler-artifact' and r.get('executable')]
        if len(binaries)!=1: raise ValueError('test binary identity')
        binary = out/(label+'-tests.exe'); shutil.copyfile(binaries[0],binary)
        record['binaries'][binary.name] = digest(binary)
        return binary
    for profile in ('debug','release'):
        binary = build(profile,profile=='release')
        output = run(profile+'-native',[str(binary),NATIVE_TEST,'--ignored','--exact','--nocapture'])
        if 'cases=68;' not in output or '1 passed; 0 failed' not in output: raise ValueError('native population')
        output = run(profile+'-lifecycle',[str(binary),'windows_enclave::'])
        if '0 failed' not in output or 'running 0 tests' in output: raise ValueError('empty regressions')
        print(profile+': 68 native cases and Windows lifecycle regressions PASS',flush=True)
    native = ROOT/'crates/brynja-crypto-cpu-std/src/windows_enclave/native/parallel_concurrent'
    for index,(name,needle,replacement) in enumerate(MUTANTS):
        source = native/name
        original = source.read_bytes()
        if original.count(needle.encode()) != 1: raise ValueError('stale mutant: '+needle)
        try:
            source.write_bytes(original.replace(needle.encode(),replacement.encode()))
            changed = digest(source)
            label = f'mutant-{index}'
            binary = build(label) # A compile error never counts as rejection.
            output = run(label+'-native',[str(binary),NATIVE_TEST,'--ignored','--exact','--nocapture'],101)
            if 'test result: FAILED.' not in output: raise ValueError('mutant did not reach a test assertion')
            record['mutations'].append(dict(source=name,before=needle,after=replacement,
                mutated_sha256=changed,binary=binary.name))
            print('REJECTED: '+needle,flush=True)
        finally: source.write_bytes(original)
    binary = build('restored')
    output = run('restored-native',[str(binary),NATIVE_TEST,'--ignored','--exact','--nocapture'])
    if 'cases=68;' not in output or '1 passed; 0 failed' not in output: raise ValueError('restored population')
    run('clippy',['cargo','+1.98.1','clippy','--locked','--offline','-p','brynja-crypto-cpu-std',
        '--features','strict-sha2,strict-sha3-acceleration','--all-targets','--','-D','warnings',
        '-A','clippy::chunks_exact_to_as_chunks'])
    if sources()!=before or digest(image)!=record['image_sha256']: raise ValueError('source/image changed')
    record.update(status='CRATE_PARALLEL_CONCURRENT_DEVELOPMENT_PASS',enclave_execution=True)
    (out/'host-results.json').write_text(json.dumps(record,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image',type=Path); parser.add_argument('directory',type=Path)
    args=parser.parse_args()
    capture(args.image.resolve(strict=True),args.directory.resolve())
