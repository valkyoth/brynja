"""Private multi-wave oracle, mutation and compiled ownership regressions."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import windows_enclave_parallel_waves_build as build

MUTANTS = (
    ('if expected_leaves > MAX_LEAVES', 'if expected_leaves > MAX_LEAVES + 1'),
    ('if !self.complete {', 'if false {'),
    ('self.state = State::Empty;', ''),
    ('clear_owned_region(&mut self.output)', 'clear_owned_region(&mut self.output[..0])'),
    ('op.root.consumed_bits >= op.root.total_bits', 'false'),
    ('let offset = op.root.consumed_bits / 8;', 'let offset = 0;'),
    ('plan.claimed.store(true, Ordering::Release)', 'plan.claimed.store(false, Ordering::Release)'),
    ('plan.check()?;', ''),
    ('op.root.consumed_bits != op.root.total_bits', 'false'),
    ('op.root.merged_leaves != op.root.expected_leaves', 'false'),
    ('framing.right(u128::try_from(op.root.merged_leaves).map_err(|_| Error::Length)?)?', 'framing.right(0)?'),
    ('u128::try_from(op.root.output_bits).map_err(|_| Error::Length)?', '0'),
    ('framing.left(u128::try_from(block).map_err(|_| Error::Length)?)?', 'framing.right(u128::try_from(block).map_err(|_| Error::Length)?)?'),
    ('check_authority(op.root.authority)?;\n        let (width, _) = shape(op.root.output_bits)?;',
     'let (width, _) = shape(op.root.output_bits)?;'),
)


def run(command):
    return subprocess.run(command, capture_output=True, text=True, timeout=180)


def negatives(command, directory):
    common = command[:command.index('--crate-name')]
    dependencies = [part for name in ('parallel_waves', 'brynja_crypto_cpu', 'brynja_hash_sha3')
                    for part in ('--extern', name + '=' + str(directory / ('lib' + name + '.rlib')))]
    setup = ('let authority=brynja_crypto_cpu::static_execution::Authority::new('
        'brynja_crypto_cpu::static_execution::Kernel::X86Keccak).unwrap(); '
        'let empty=brynja_hash_sha3::Fips202BitString::new(&[],0).unwrap(); '
        'let mut root=parallel_waves::Waves::new(&authority,1,1,32,empty,256).unwrap(); ')
    probes = [(trait, f"fn need<T: {trait}>(){{}} fn main(){{need::<parallel_waves::Waves<'static>>();}}", 'E0277')
              for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug')]
    probes += [(name, 'fn main(){' + setup + body + '}', error) for name, body, error in (
        ('root-reentry', 'let _=root.wave(|_,_,_| {root.finish()?; Ok(())});', 'E0499'),
        ('root-drop', 'let _=root.wave(|_,_,_| {drop(root); Ok(())});', 'E0505'),
        ('slot-escape', 'let mut saved=None; let _=root.wave(|_,_,s|{saved=Some(&mut s[0]); Ok(())}); let _=saved;', 'E0521'),
        ('plan-escape', 'let mut saved=None; let _=root.wave(|_,p,_|{saved=Some(p); Ok(())}); let _=saved;', 'E0521'),
        ('private-state', 'let _=root.state;', 'E0616'),
        ('private-output', 'let _=root.output;', 'E0616'),
    )]
    records = []
    for name, source, error in probes:
        path = directory / 'negative.rs'
        path.write_text(source)
        result = run(common + ['--crate-name', 'negative', str(path), '--emit=metadata',
                              '-o', str(directory / 'negative.rmeta')] + dependencies)
        if result.returncode == 0 or error not in result.stderr:
            raise AssertionError(name + '\n' + result.stderr)
        records.append(dict(name=name, diagnostic=error, stderr=result.stderr))
    return records


def check(directory, baseline_only):
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    command, binary = build.build(directory, target)
    result = run([str(binary), '--nocapture'])
    if result.returncode or '21 passed; 0 failed' not in result.stdout:
        raise AssertionError(result.stdout + result.stderr)
    print(result.stdout, flush=True)
    initial = result.stdout
    mutations = []
    path = directory / 'parallel_concurrent_waves.rs'
    original = path.read_bytes()
    if not baseline_only:
        try:
            for number, (before, after) in enumerate(MUTANTS):
                text = original.decode('utf-8')
                if text.count(before) != 1: raise ValueError('mutation anchor: ' + before)
                path.write_bytes(text.replace(before, after).encode('utf-8'))
                mutant = directory / ('wave-mutant-' + str(number) + ('.exe' if 'windows' in target else ''))
                args = list(command)
                args[args.index('-o') + 1] = str(mutant)
                compiled = run(args)
                if compiled.returncode: raise AssertionError('mutant must compile: ' + compiled.stderr)
                result = run([str(mutant), 'parallel_concurrent_waves_tests::', '--nocapture'])
                if result.returncode != 101 or 'test result: FAILED.' not in result.stdout or '\nrunning 0 tests\n' in result.stdout:
                    raise AssertionError('mutant escaped: ' + before + '\n' + result.stdout + result.stderr)
                mutations.append(dict(before=before, after=after, output=result.stdout, stderr=result.stderr))
                print('REJECTED: ' + before, flush=True)
        finally:
            path.write_bytes(original)
    rejected = negatives(command, directory)
    record = json.loads((directory / 'parallel-waves-build.json').read_text())
    for name, digest in record['source_sha256'].items():
        assert hashlib.sha256((build.ROOT / name).read_bytes()).hexdigest() == digest, name
    for name, digest in record['generated_sha256'].items():
        assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == digest, name
    result = run([str(binary), '--nocapture'])
    if result.returncode or '21 passed; 0 failed' not in result.stdout:
        raise AssertionError(result.stdout + result.stderr)
    record.update(status='PRIVATE_MULTI_WAVE_COMPONENT_PASS', full_mutation_campaign=not baseline_only,
                  initial=initial, final=result.stdout, mutations=mutations, negatives=rejected,
                  binary=binary.name, binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    (directory / 'parallel-waves-results.json').write_text(json.dumps(record, indent=2) + '\n')
    print(f"Private multi-wave component: PASS; {record['wave_oracle_cases']} oracle cases x two orders; {len(mutations)} mutants; {len(rejected)} compiled negatives; NOT enclave execution")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--baseline-only', action='store_true')
    args = parser.parse_args()
    check(args.directory.resolve(), args.baseline_only)
