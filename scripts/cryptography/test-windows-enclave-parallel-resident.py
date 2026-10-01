#!/usr/bin/env python3
"""Private sequential AVX2 batch placement tests, not enclave qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import windows_enclave_parallel_accelerated_build as base

FILES = ('parallel_accelerated_resident.rs', 'parallel_accelerated_resident_tests.rs')


def invoke(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError(str(command)+'\n'+result.stdout+result.stderr)
    return result.stdout


def run(directory, target):
    component, binary = base.build(directory, target)
    output = invoke([str(binary)])
    if '20 passed; 0 failed' not in output: raise AssertionError(output)
    record = json.loads((directory/'parallel-accelerated-build.json').read_text())
    common = component[:component.index('--crate-name')]
    for name in FILES: shutil.copyfile(base.SOURCE/name, directory/name)
    deps = [part for name in ('parallel_accelerated', 'brynja_crypto_cpu')
            for part in ('--extern', name+'='+str(directory/('lib'+name+'.rlib')))]
    compile_base = common+['--crate-name', 'parallel_accelerated_resident', str(directory/FILES[0])]+deps
    library = compile_base+['--crate-type', 'rlib', '-o', str(directory/'libparallel_accelerated_resident.rlib')]
    test_binary = directory/('parallel-resident-test.exe' if 'windows' in target else 'parallel-resident-test')
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
            mutants.append(dict(before=before, after=after, output=execute(False)))
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
        probe.write_text('use parallel_accelerated_resident::{Resident, Page};\n'+source)
        result = subprocess.run(common+['-A', 'unused_imports', '--crate-name', 'negative', str(probe),
            '--emit=metadata', '-o', str(directory/'negative.rmeta'), '--extern',
            'parallel_accelerated_resident='+str(directory/'libparallel_accelerated_resident.rlib')],
            capture_output=True, text=True, timeout=120)
        if not result.returncode or diagnostic not in result.stderr: raise AssertionError(result.stderr)
        negatives.append(dict(name=name, diagnostic=diagnostic, stderr=result.stderr))
    for name, digest in record['generated_sha256'].items():
        assert hashlib.sha256((directory/name).read_bytes()).hexdigest() == digest
    paths = [base.SOURCE/name for name in FILES]+[Path(__file__).resolve()]
    record['source_sha256'].update({p.relative_to(base.ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    record['generated_sha256'].update({name: hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in FILES})
    record.update(status='SEQUENTIAL_AVX2_PARALLELHASH_RESIDENT_PASS', enclave_execution=False,
        production_qualified=False, component_output=output, initial=initial, final=final,
        mutations=mutants, negatives=negatives, resident_commands=[library, command],
        binary_sha256=hashlib.sha256(test_binary.read_bytes()).hexdigest())
    (directory/'parallel-resident-results.json').write_text(json.dumps(record, indent=2)+'\n')
    print('Batch resident: 332 independent cases; 3 placement mutants; 7 ownership negatives; no enclave qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    run(args.directory.resolve(), target)
