"""Bounded process-only generation/reuse races and compiled regression mutants."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

import windows_enclave_parallel_wave_bridge_build as build
from windows_enclave_parallel_accelerated_worker_build import replace_exact


def run(command, env=None):
    return subprocess.run(command, env=env, capture_output=True, text=True, timeout=45)


def negatives(command, directory):
    common = command[:command.index('--crate-name')]
    deps = ['--extern', 'parallel_wave_gate=' + str(directory / 'libparallel_wave_gate.rlib')]
    probes = [(trait, f"fn need<T:{trait}>(){{}} fn main(){{need::<parallel_wave_gate::Wave<'static>>();}}", 'E0277')
              for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug')]
    probes += [
        ('ticket-clone', "fn need<T:Clone>(){} fn main(){need::<parallel_wave_gate::Ticket<'static>>();}", 'E0277'),
        ('private-generation', 'fn main(){let gate=parallel_wave_gate::Gate::new();let mut w=gate.reserve(1).unwrap();w.generation=9;}', 'E0616'),
        ('private-retirement', 'fn main(){let gate=parallel_wave_gate::Gate::new();let mut w=gate.reserve(1).unwrap();w.retired=true;}', 'E0616'),
        ('ticket-escape', "fn escape()->parallel_wave_gate::Ticket<'static>{let gate=parallel_wave_gate::Gate::new();let w=gate.reserve(1).unwrap();w.publish();gate.enter(1,0).unwrap()} fn main(){}", 'E0515'),
    ]
    results = []
    for name, source, error in probes:
        path = directory / 'negative.rs'
        path.write_text(source)
        result = run(common + ['--crate-name', 'negative', str(path), '--emit=metadata',
                               '-o', str(directory / 'negative.rmeta')] + deps)
        if result.returncode == 0 or error not in result.stderr:
            raise AssertionError(name + '\n' + result.stderr)
        results.append(dict(name=name, diagnostic=error, stderr=result.stderr))
    return results


def bridge_mutants(command, directory):
    source = directory / 'parallel_wave_bridge.rs'
    original = source.read_bytes()
    mutations = (
        ('const TOTAL_BITS: usize = 32 * 9 * 8 + 3;', 'const TOTAL_BITS: usize = 32 * 9 * 8 + 2;'),
        ('OFFSET.store(offset, Ordering::Relaxed);', 'OFFSET.store(0, Ordering::Relaxed);'),
        ('for _ in 0..3 {', 'for _ in 0..2 {'),
        ('pointer.store(core::ptr::null_mut(), Ordering::Relaxed);', 'let _ = pointer;'),
    )
    results = []
    try:
        for number, (before, after) in enumerate(mutations):
            source.write_bytes(replace_exact(original.decode(), before, after).encode())
            changed = list(command)
            binary = directory / ('adapter-mutant-' + str(number) + ('.exe' if os.name == 'nt' else ''))
            changed[changed.index('-o') + 1] = str(binary)
            compiled = run(changed + ['-A', 'unused_variables'])
            if compiled.returncode: raise AssertionError('adapter mutant must compile: ' + compiled.stderr)
            env = dict(os.environ, BRYNJA_WAVE_ID='1', BRYNJA_WAVE_MODE='normal', BRYNJA_WAVE_FAIL_AT='1')
            result = run([str(binary), '--test-threads=1'], env)
            if result.returncode != 101 or '1 failed' not in result.stdout or 'test result: FAILED.' not in result.stdout:
                raise AssertionError(f'adapter mutant {number} escaped/crashed: ' + result.stdout + result.stderr)
            results.append(dict(number=number, output=result.stdout))
    finally:
        source.write_bytes(original)
    return results


def check(directory):
    record = json.loads((directory / 'parallel-wave-bridge-build.json').read_text())
    gate_command, bridge_command = record['commands'][-2:]
    gate_binary = gate_command[gate_command.index('-o') + 1]
    bridge_binary = bridge_command[bridge_command.index('-o') + 1]
    result = run([gate_binary, '--test-threads=1'])
    if result.returncode or '10 passed' not in result.stdout:
        raise AssertionError(result.stdout + result.stderr)
    gate_tests = result.stdout
    cases = []
    for identity in range(1, 5):
        for mode in ('normal', 'early', 'empty', 'missing', 'cancel', 'unwind'):
            for fail_at in ((1,) if mode == 'normal' else (1, 2, 3)):
                env = dict(os.environ, BRYNJA_WAVE_ID=str(identity), BRYNJA_WAVE_MODE=mode,
                           BRYNJA_WAVE_FAIL_AT=str(fail_at))
                result = run([bridge_binary, '--test-threads=1'], env)
                if result.returncode or '1 passed' not in result.stdout:
                    raise AssertionError(f'{identity=} {mode=} {fail_at=}\n' + result.stdout + result.stderr)
                cases.append(dict(identity=identity, mode=mode, fail_at=fail_at, output=result.stdout))
    gate = directory / 'parallel_wave_gate.rs'
    original = gate.read_bytes()
    exact = 'tests::exact_generation_lane_and_one_shot_publication'
    partial = 'tests::partial_waves_require_exact_success_and_release'
    mutations = (
        ('state >> 32 != u64::from(generation)', 'false', 'tests::retired_generation_rejects_during_next_open_wave'),
        ('|| state & OPEN == 0', '|| false', exact),
        ('|| state & bit != 0', '|| false', exact),
        ('|| state & (bit << 12) == 0', '|| false', exact),
        ('state | bit | (bit << 4)', 'state | bit', partial),
        ('Some((state & !OPEN) | CLOSED)', 'Some(state | CLOSED)', 'tests::empty_closed_wave_cannot_reopen'),
        ('Some((state & !OPEN) | CLOSED)', 'Some(state & !OPEN)', 'tests::empty_closed_wave_cannot_reopen'),
        ('&& (state >> 8) & 15 == expected', '&& true', 'tests::incomplete_or_unwound_workers_never_commit'),
        ('self.gate.0.load(Ordering::Acquire) & (OPEN | LIVE | CLOSED) == CLOSED',
         'self.gate.0.load(Ordering::Acquire) & (OPEN | CLOSED) == CLOSED', exact),
        ('self.retired || state & (OPEN | LIVE | CLOSED) != CLOSED',
         'self.retired || state & (OPEN | CLOSED) != CLOSED', partial),
        ('previous & LOW != 0', 'false', exact),
        ('checked_add(1)?', 'wrapping_add(1)', 'tests::generation_exhaustion_never_wraps_or_reauthorizes'),
        ('self.gate.0.fetch_or(self.lane << 8, Ordering::Release);', 'let _ = self.lane;', partial),
        ('self.gate.0.fetch_and(!(self.lane << 4), Ordering::Release);', 'let _ = self.lane;', exact),
        ('self.close();', 'let _ = &self.gate;', 'tests::abandoned_or_unwound_root_seals_gate'),
    )
    results = []
    try:
        for number, (before, after, test) in enumerate(mutations):
            gate.write_bytes(replace_exact(original.decode(), before, after).encode())
            command = list(gate_command)
            artifact = directory / ('generation-mutant-' + str(number) + ('.exe' if os.name == 'nt' else ''))
            command[command.index('-o') + 1] = str(artifact)
            command += ['-A', 'dead_code', '-A', 'unused_variables']
            compiled = run(command)
            if compiled.returncode:
                raise AssertionError('mutant must compile: ' + compiled.stderr)
            result = run([str(artifact), test, '--exact'])
            if result.returncode != 101 or '1 failed' not in result.stdout or 'test result: FAILED.' not in result.stdout:
                raise AssertionError(f'gate mutant {number} escaped or crashed: ' + result.stdout + result.stderr)
            results.append(dict(number=number, test=test, output=result.stdout))
    finally:
        gate.write_bytes(original)
    rejected = negatives(gate_command, directory)
    adapter_mutations = bridge_mutants(bridge_command, directory)
    for name, digest in record['source_sha256'].items():
        if hashlib.sha256((build.ROOT / name).read_bytes()).hexdigest() != digest:
            raise AssertionError('repository source drift: ' + name)
    for name, digest in record['generated_sha256'].items():
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest:
            raise AssertionError('generated source drift: ' + name)
    result = dict(schema=1, status='PRIVATE_GENERATION_BRIDGE_PROCESS_PASS', enclave_execution=False,
        production_qualified=False, source_sha256=record['source_sha256'],
        artifact_sha256={Path(p).name: hashlib.sha256(Path(p).read_bytes()).hexdigest()
                        for p in (gate_binary, bridge_binary)}, gate_tests=gate_tests,
        cases=cases, mutations=results, adapter_mutations=adapter_mutations, negatives=rejected)
    (directory / 'parallel-wave-bridge-results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f'Private wave bridge: 10 gate tests; {len(cases)} identity/fault cases; {len(results)} gate + {len(adapter_mutations)} adapter mutants; {len(rejected)} compiled negatives rejected')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    check(parser.parse_args().directory.resolve())
