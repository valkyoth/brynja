#!/usr/bin/env python3
"""Private sequential SHA-NI batch placement tests, not enclave qualification."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import windows_enclave_sha2_batch_accelerated_build as base

FILES = ('sha2_batch_accelerated_resident.rs', 'sha2_batch_accelerated_resident_tests.rs')


def invoke(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError(str(command)+'\n'+result.stdout+result.stderr)
    return result.stdout


def run(directory, target):
    component, binary = base.build(directory, target)
    output = invoke([str(binary)])
    if '12 passed; 0 failed' not in output: raise AssertionError(output)
    record = json.loads((directory/'sha2-batch-accelerated-build.json').read_text())
    common = component[:component.index('--crate-name')]
    for name in FILES: shutil.copyfile(base.SOURCE/name, directory/name)
    oracle_path = base.ROOT/'scripts/sha2/check-sha2-bit-differential.py'
    spec = importlib.util.spec_from_file_location('bit_oracle', oracle_path)
    oracle = importlib.util.module_from_spec(spec); spec.loader.exec_module(oracle)
    rows = []
    for identity, name in ((1, 'sha224'), (2, 'sha256')):
        for length in (0, 1, 7, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 1023, 1024, 2049):
            for last in (range(1, 9) if length else (0,)):
                data = bytearray((i*17) % 256 for i in range(length))
                if data: data[-1] &= (255 << (8-last)) & 255
                expected = oracle.digest32(data, max(0, length-1)*8+last, *oracle.CONFIG[name])
                if last in (0, 8): assert expected == hashlib.new(name, data).hexdigest()
                rows.append(f'{identity} {last} {data.hex() or "-"} {expected}')
    assert len(rows) == 242
    oracle_file = directory/'sha2-batch-resident-oracle.txt'
    oracle_file.write_text('\n'.join(rows)+'\n')
    deps = [part for name in ('sha2_batch_accelerated', 'brynja_crypto_cpu', 'brynja_hash_sha2')
            for part in ('--extern', name+'='+str(directory/('lib'+name+'.rlib')))]
    compile_base = common+['--crate-name', 'sha2_batch_accelerated_resident', str(directory/FILES[0])]+deps
    library = compile_base+['--crate-type', 'rlib', '-o', str(directory/'libsha2_batch_accelerated_resident.rlib')]
    test_binary = directory/('batch-resident-test.exe' if 'windows' in target else 'batch-resident-test')
    command = compile_base+['--test', '-o', str(test_binary)]
    invoke(library)
    def execute(success):
        invoke(command)
        result = subprocess.run([str(test_binary)], capture_output=True, text=True, timeout=180)
        token = '3 passed; 0 failed' if success else 'FAILED'
        if (result.returncode == 0) != success or token not in result.stdout:
            raise AssertionError(result.stdout+result.stderr)
        return result.stdout+result.stderr
    initial = execute(True)
    print(initial, flush=True)
    path = directory/FILES[0]
    original = path.read_bytes()
    mutants = []
    for before, after in (
        ('owner.quarantine();', ''),
        ('unsafe { self.owner.as_mut() }.quarantine();', 'let _ = unsafe { self.owner.as_mut() };'),
        ('pointer.as_ptr().add(offset).write_volatile(0)', 'pointer.as_ptr().add(offset).write_volatile(0xa5)'),
    ):
        if original.decode().count(before) != 1: raise AssertionError('Stale mutant: '+before)
        try:
            path.write_text(original.decode().replace(before, after))
            try: mutant_output = execute(False)
            except AssertionError as error: raise AssertionError('Survived mutant: '+before+'\n'+str(error)) from error
            mutants.append(dict(before=before, after=after, output=mutant_output))
        finally: path.write_bytes(original)
    final = execute(True)
    negatives = []
    for name, source, diagnostic in [
        *[(trait, 'fn need<T: '+trait+'>() {} fn main() { need::<Resident>(); }', 'E0277')
          for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug')],
        ('escape', "fn escape() -> Resident<'static> { let mut p = Page::empty(); Resident::new(&mut p).unwrap() } fn main() {}", 'E0515'),
        ('move-page', 'fn main() { let mut p = Page::empty(); let r = Resident::new(&mut p).unwrap(); drop(p); drop(r); }', 'E0505'),
    ]:
        probe = directory/'negative.rs'
        probe.write_text('use sha2_batch_accelerated_resident::{Resident, Page};\n'+source)
        result = subprocess.run(common+['-A', 'unused_imports', '--crate-name', 'negative', str(probe),
            '--emit=metadata', '-o', str(directory/'negative.rmeta'), '--extern',
            'sha2_batch_accelerated_resident='+str(directory/'libsha2_batch_accelerated_resident.rlib')],
            capture_output=True, text=True, timeout=120)
        if not result.returncode or diagnostic not in result.stderr: raise AssertionError(result.stderr)
        negatives.append(dict(name=name, diagnostic=diagnostic, stderr=result.stderr))
    for name, digest in record['generated_sha256'].items():
        assert hashlib.sha256((directory/name).read_bytes()).hexdigest() == digest
    paths = [base.SOURCE/name for name in FILES]+[Path(__file__).resolve(), oracle_path]
    record['source_sha256'].update({p.relative_to(base.ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    record['generated_sha256'].update({name: hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in FILES})
    record['generated_sha256'][oracle_file.name] = hashlib.sha256(oracle_file.read_bytes()).hexdigest()
    record.update(status='SEQUENTIAL_SHA_NI_BATCH_RESIDENT_PASS', enclave_execution=False,
        production_qualified=False, component_output=output, initial=initial, final=final,
        mutations=mutants, negatives=negatives, resident_commands=[library, command],
        binary_sha256=hashlib.sha256(test_binary.read_bytes()).hexdigest())
    (directory/'sha2-batch-resident-results.json').write_text(json.dumps(record, indent=2)+'\n')
    print('SHA-NI batch resident: 242 independent bit cases; 255 mixed-slot masks; 3 placement mutants; 7 ownership negatives; no enclave qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--attest-native-bundle', action='store_true', required=True)
    args = parser.parse_args()
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    if not target.startswith('x86_64-'): parser.error('Native SHA/SSE2/AVX/AVX2 required')
    run(args.directory.resolve(), target)
