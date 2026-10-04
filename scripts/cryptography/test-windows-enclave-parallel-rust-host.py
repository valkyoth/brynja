"""Private Windows Rust/VBS host capture with mandatory cleanup on failed cases."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import windows_enclave_parallel_rust_host_build as build

MUTANTS = (
    ('adapter/transport/callbacks.rs', 'frame.locked = true;', 'frame.locked = false;'),
    ('adapter/transport/callbacks.rs', '!sys::lock(low, 65536, false)', 'false'),
    ('adapter/transport/callbacks.rs', 'frame.verified = true;', 'frame.verified = false;'),
    ('adapter/transport/callbacks.rs', 'frame.phase = 2;', 'frame.phase = 1;'),
    ('adapter/transport/callbacks.rs', 'if result == Ok(1)', 'if result == Ok(2)'),
    ('adapter/transport.rs', 'returned != 1', 'returned != 2'),
    ('image.rs', 'u32_at(b, add(c, 72)?)? == 5', 'u32_at(b, add(c, 72)?)? == 1'),
    ('adapter/transport.rs', 'pin.signature()?;', '/* production signature bypass */'),
)


def run(command):
    return subprocess.run(command, capture_output=True, text=True, timeout=90)


def checked(command):
    result = run(command)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def mutant_bytes(original, before, after):
    # Preserve CRLF bytes: Windows text-mode output would turn existing CRLF
    # into CRCRLF, producing a compiler error instead of a runtime mutation.
    return build.replace(original.decode('utf-8'), before, after).encode('utf-8')


def campaign(directory, image):
    build.build(directory, image)
    record = json.loads((directory / 'rust-host-build.json').read_text())
    command = record['commands'][-1]
    clippy = ['rustup', 'run', '1.98.1', 'clippy-driver'] + command[2:]
    clippy[clippy.index('-o')+1] = str(directory / 'host-clippy.rmeta')
    clippy += ['--emit=metadata']
    checked(clippy)
    binary = directory / 'rust-host.exe'
    outputs = []
    for index, case in enumerate(record['cases']):
        result = checked([str(binary), str(image), str(index)])
        expected = f'RUST_SCOPED_VBS: case={index}; fault={case["fault"]}; PASS\n'
        if result.stdout != expected or result.stderr: raise AssertionError('incomplete native case')
        outputs.append(result.stdout)
        print(result.stdout, end='', flush=True)
    mutants = []
    for index, (relative, before, after) in enumerate(MUTANTS):
        source = directory / relative
        original = source.read_bytes()
        mutant = directory / f'host-mutant-{index}.exe'
        try:
            source.write_bytes(mutant_bytes(original, before, after))
            args = list(command)
            args[args.index('-o')+1] = str(mutant)
            checked(args) # compilation failures never count as rejected mutations
            result = run([str(mutant), str(image), '4']) # multi-wave, four workers
            if result.returncode != 1 or result.stdout or not result.stderr.startswith('RUST_SCOPED_VBS: '):
                raise AssertionError('mutant escaped or crashed: ' + relative + '\n' + result.stdout + result.stderr)
            mutants.append(dict(source=relative, before=before, stderr=result.stderr,
                                binary=mutant.name, binary_sha256=digest(mutant)))
            print('REJECTED: ' + before, flush=True)
        finally: source.write_bytes(original)
    negatives = []
    for relative, owner in (('adapter/transport.rs', 'Enclave'), ('adapter/transport/callbacks.rs', 'Installed')):
        source = directory / relative
        original = source.read_bytes()
        try:
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                source.write_bytes(original + ('\nfn rejected_bound(){fn need<T:'+bound+'>(){}need::<'+owner+'>();}\n').encode())
                args = list(command)
                args[args.index('-o')+1] = str(directory / 'negative.rmeta')
                args += ['--emit=metadata']
                result = run(args)
                if result.returncode == 0 or 'E0277' not in result.stderr:
                    raise AssertionError('owner bound escaped: ' + owner + '/' + bound + '\n' + result.stderr)
                negatives.append(dict(owner=owner, bound=bound, diagnostic=result.stderr))
        finally: source.write_bytes(original)
    for name, value in record['source_sha256'].items():
        if digest(build.ROOT / name) != value: raise AssertionError('source changed: ' + name)
    for name, value in record['artifact_sha256'].items():
        if digest(directory / name) != value: raise AssertionError('artifact changed: ' + name)
    if digest(image) != record['image_sha256']: raise AssertionError('image changed')
    # Fresh process after source restoration; the original binary is unchanged.
    final = checked([str(binary), str(image), '21'])
    if final.stdout != outputs[21] or final.stderr: raise AssertionError('final long-wave regression')
    record.update(status='PRIVATE_RUST_SCOPED_VBS_HOST_PASS', enclave_execution=True,
        production_qualified=False, production_signed=False, whole_image_cleanup_qualified=False,
        clippy_command=clippy, outputs=outputs, mutations=mutants, negatives=negatives, final=final.stdout,
        runner_sha256=digest(Path(__file__)))
    (directory / 'rust-host-results.json').write_text(json.dumps(record, indent=2)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('image', type=Path)
    args = parser.parse_args()
    campaign(args.directory.resolve(), args.image.resolve(strict=True))
