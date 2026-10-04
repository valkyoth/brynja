"""Private Rust host scheduler: real scoped threads, faults and ownership checks.

Ordinary process evidence only; does not load an enclave or qualify OS residency.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'assurance/windows-enclave-probe'
FILES = ('parallel_host_scheduler.rs', 'parallel_host_scheduler_tests.rs')
MUTANTS = (
    ('leaves > MAX_LEAVES', 'leaves > MAX_LEAVES + 1'),
    ('self.phase = Phase::Failed;', 'let _ = Phase::Failed;', 3),
    ('native != (u64::from(generation) << 32) | (mask << 12) | OPEN', 'false'),
    ('failed = Some(error);', 'let _ = error;'),
    ('failed = Some(Error::Worker);', 'failed = None;'),
    ('previous != Phase::Close', 'false'),
    ('previous != Phase::Complete || native != expected', 'native != expected'),
    ('native != expected', 'native == expected.wrapping_add(1)'),
    ('self.completed = generation;', 'self.completed = generation - 1;'),
    ('u64::from(self.completed) != self.leaves.div_ceil(4)', 'false'),
    ('native != u64::from(self.completed) << 32', 'false'),
    ('u64::from(self.generation) * 16 +', 'u64::from(self.generation) * 32 +'),
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command):
    return subprocess.run(command, capture_output=True, text=True, timeout=90)


def require_compile(command):
    result = run(command)
    if result.returncode:
        raise RuntimeError('compilation must succeed: ' + result.stdout + result.stderr)
    return result


def check(directory):
    directory.mkdir(parents=True, exist_ok=False)
    for name in FILES:
        shutil.copyfile(SOURCE / name, directory / name)
    host = require_compile(['rustc', '+1.98.1', '-vV']).stdout
    suffix = '.exe' if 'host: x86_64-pc-windows-msvc' in host else ''
    source = directory / FILES[0]
    library = directory / 'libscheduler.rlib'
    common = ['rustc', '+1.98.1', '--edition=2024', '-Dwarnings', '--crate-name', 'scheduler']
    require_compile(common + ['--crate-type=rlib', str(source), '-o', str(library)])
    command = common + ['--test', str(source), '-o']
    binary = directory / ('host-scheduler' + suffix)
    require_compile(command + [str(binary)])
    result = run([str(binary)])
    if result.returncode or '8 passed; 0 failed' not in result.stdout:
        raise AssertionError(result.stdout + result.stderr)
    baseline = result.stdout
    print(baseline, flush=True)
    clippy = ['rustup', 'run', '1.98.1', 'clippy-driver', '--edition=2024', '-Dwarnings',
              '--crate-name', 'scheduler', '--crate-type=rlib', str(source), '--emit=metadata',
              '-o', str(directory / 'clippy.rmeta')]
    require_compile(clippy)
    original = source.read_text()
    mutations = []
    try:
        for index, mutation in enumerate(MUTANTS):
            before, after = mutation[:2]
            count = mutation[2] if len(mutation) == 3 else 1
            if original.count(before) != count:
                raise AssertionError('mutation source anchor: ' + before)
            source.write_text(original.replace(before, after))
            mutant = directory / (f'mutant-{index}' + suffix)
            # Removed gates can leave metadata unused; only that warning is
            # allowed for mutations. Baseline and Clippy allow no warnings.
            require_compile(command + [str(mutant), '-Aunused-variables'])
            result = run([str(mutant)])
            if result.returncode != 101 or 'test result: FAILED.' not in result.stdout:
                raise AssertionError('mutant escaped or crashed: ' + before + '\n' + result.stdout + result.stderr)
            mutations.append(dict(before=before, stdout=result.stdout, stderr=result.stderr,
                                  binary=mutant.name, binary_sha256=digest(mutant)))
            print('REJECTED: ' + before, flush=True)
    finally:
        source.write_text(original)
    negatives = []
    probes = [(trait, f'fn need<T:{trait}>(){{}} fn main(){{need::<scheduler::Scheduler>();}}', 'E0277')
              for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug')]
    probes += [
        ('private-state', 'fn main(){let s=scheduler::Scheduler::new(0,1).unwrap(); let _=s.completed;}', 'E0616'),
        ('private-work', 'fn main(){let _=scheduler::Work{generation:1,lane:0};}', 'E0451'),
        ('consuming-finish', 'fn main(){let s=scheduler::Scheduler::new(0,1).unwrap(); let _=s.finish(0); let _=s.finish(0);}', 'E0382'),
        ('scoped-borrow-escape', 'fn main(){let local=String::new();let mut s=scheduler::Scheduler::new(1,1).unwrap();let f=|_|{std::thread::spawn(|| println!("{}",local));Ok(())};let _=s.dispatch(0,&f);}', 'E0597'),
    ]
    for name, text, diagnostic in probes:
        path = directory / 'negative.rs'
        path.write_text(text)
        result = run(common + [str(path), '--extern', 'scheduler=' + str(library), '--emit=metadata',
                               '-o', str(directory / 'negative.rmeta')])
        if result.returncode == 0 or diagnostic not in result.stderr:
            raise AssertionError('negative diagnostic mismatch: ' + name + '\n' + result.stderr)
        negatives.append(dict(name=name, diagnostic=diagnostic, stderr=result.stderr))
    final = run([str(binary)])
    if final.returncode or '8 passed; 0 failed' not in final.stdout:
        raise AssertionError('final baseline failed: ' + final.stdout + final.stderr)
    source_paths = [SOURCE / name for name in FILES] + [Path(__file__).resolve()]
    record = dict(status='PRIVATE_SCOPED_HOST_COMPONENT_PASS', enclave_execution=False,
                  production_qualified=False, compiler=host, baseline=baseline, final=final.stdout,
                  commands=[common + ['--crate-type=rlib', str(source), '-o', str(library)],
                            command + [str(binary)], clippy], mutations=mutations, negatives=negatives,
                  binary=binary.name, binary_sha256=digest(binary),
                  source_sha256={p.relative_to(ROOT).as_posix(): digest(p) for p in source_paths},
                  generated_sha256={name: digest(directory / name) for name in FILES})
    (directory / 'host-scheduler-results.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Scoped host scheduler: 8 tests, 12 runtime mutants, 9 ownership negatives PASS; NOT VBS execution')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    check(parser.parse_args().directory.resolve())
