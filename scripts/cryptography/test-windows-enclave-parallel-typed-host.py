"""Real VBS execution through the private typed public-output API candidate."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import windows_enclave_parallel_rust_host_build as base

FILES = ('parallel_host_contract.rs', 'parallel_host_contract_transport.rs', 'parallel_host_contract_native.rs')
MUTANTS = (
    ('contract.rs', 'self.state = State::Quarantined;', 'self.state = State::Ready;', 25),
    ('contract.rs', 'if output.len() != plan.output_bytes()', 'if output.len() > 1025', 4),
    ('contract.rs', '        result?;', '        let _ = result;', 25),
    ('contract.rs', 'self.state = State::Complete;', 'self.state = State::Ready;', 4),
    ('contract.rs', 'Self::ParallelHashXof128 => 3', 'Self::ParallelHashXof128 => 1', 14),
    ('contract.rs', 'self.input.custom.address()?', 'self.input.message.address()?', 4),
    ('adapter/transport/callbacks.rs', '!sys::lock(low, 65536, false)', 'false', 4),
)


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command): return subprocess.run(command, capture_output=True, text=True, timeout=120)


def checked(command):
    result = run(command)
    if result.returncode: raise RuntimeError(result.stdout+result.stderr)
    return result


def campaign(directory, image):
    base.build(directory, image)
    record = json.loads((directory/'rust-host-build.json').read_text())
    for name in FILES: shutil.copyfile(base.SOURCE/name, directory/name)
    shutil.copyfile(base.SOURCE/FILES[0], directory/'contract.rs')
    main = (base.SOURCE/'parallel_host_windows_main.rs').read_text().split('fn run()')[0]
    main += 'mod contract;\n#[path="parallel_host_contract_transport.rs"] mod contract_transport;\n'
    main += (base.SOURCE/FILES[2]).read_text().replace('//! Appended only to the private public-oracle Windows executable.',
        '// Private typed public-oracle executable.')
    (directory/'main.rs').write_text(main)
    # Fault selector exists ONLY in the native fixture, never the typed API.
    transport = directory/FILES[1]
    original = transport.read_bytes()
    before = b'self.execute(&request.header()?, output, 0)'
    if original.count(before) != 1: raise AssertionError('fault transform anchor')
    transport.write_bytes(original.replace(before,
        b'self.execute(&request.header()?, output, crate::FAULT.load(std::sync::atomic::Ordering::Relaxed))'))
    command = record['commands'][-1]
    command[command.index('-o')+1] = str(directory/'typed-host.exe')
    checked(command)
    clippy = ['rustup','run','1.98.1','clippy-driver'] + command[2:] + ['--emit=metadata']
    clippy[clippy.index('-o')+1] = str(directory/'typed-clippy.rmeta')
    checked(clippy)
    outputs = []
    for index in range(30):
        result = checked([str(directory/'typed-host.exe'), str(image), str(index)])
        expected = f'TYPED_RUST_VBS: case={index}; rejection={str(index>=25).lower()}; PASS\n'
        if result.stdout != expected or result.stderr: raise AssertionError('native result mismatch')
        outputs.append(result.stdout)
        print(result.stdout,end='',flush=True)
    mutations = []
    for index,(name,before,after,case) in enumerate(MUTANTS):
        path = directory/name; original = path.read_bytes()
        mutant = directory/f'typed-mutant-{index}.exe'
        try:
            if original.count(before.encode()) != 1: raise AssertionError('mutation anchor '+before)
            path.write_bytes(original.replace(before.encode(), after.encode()))
            args = list(command); args[args.index('-o')+1] = str(mutant)
            checked(args)
            result = run([str(mutant),str(image),str(case)])
            if result.returncode != 1 or result.stdout or not result.stderr.startswith('TYPED_RUST_VBS: '):
                raise AssertionError('mutation escaped/crashed '+before+'\n'+result.stdout+result.stderr)
            mutations.append(dict(before=before,binary=mutant.name,binary_sha256=digest(mutant),stderr=result.stderr))
            print('REJECTED: '+before,flush=True)
        finally: path.write_bytes(original)
    final = checked([str(directory/'typed-host.exe'),str(image),'21'])
    if final.stdout != outputs[21] or final.stderr: raise AssertionError('restored final result')
    sources = set(record['source_sha256']) | {str(p.relative_to(base.ROOT).as_posix()) for p in
        [*[base.SOURCE/name for name in FILES],Path(__file__).resolve()]}
    for name,value in record['source_sha256'].items():
        if digest(base.ROOT/name) != value: raise AssertionError('source changed '+name)
    if digest(image) != record['image_sha256']: raise AssertionError('image changed')
    record.update(status='PRIVATE_TYPED_RUST_VBS_HOST_PASS',enclave_execution=True,
        production_qualified=False,production_signed=False,whole_image_cleanup_qualified=False,
        outputs=outputs,mutations=mutations,final=final.stdout,clippy_command=clippy,
        source_sha256={name:digest(base.ROOT/name) for name in sorted(sources)},
        artifact_sha256={p.relative_to(directory).as_posix():digest(p) for p in directory.rglob('*') if p.is_file()})
    (directory/'typed-host-results.json').write_text(json.dumps(record,indent=2)+'\n')


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path); parser.add_argument('image',type=Path)
    args=parser.parse_args()
    campaign(args.directory.resolve(),args.image.resolve(strict=True))
