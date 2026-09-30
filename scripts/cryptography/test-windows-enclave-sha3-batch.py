#!/usr/bin/env python3
"""Private scalar SHA-3 batch tests; not enclave or platform qualification."""
import argparse
import contextlib
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import windows_enclave_sha3_stream_build as base
import windows_enclave_sha3_batch_build as builder
import windows_enclave_sha3_batch_placement as placement

MUTANTS = (
    ('self.phase != phase', 'false'),
    ('self.sequence.checked_add(1) != Some(sequence)', 'false'),
    ('op.owner.next() != Some(slot)', 'false'),
    ('self.active != Some(slot)', 'false'),
    ('bytes > 1024', 'bytes > 2048'),
    ('op.owner.next().is_some()', 'false'),
    ('expected != op.owner.plan', 'false'),
    ('if !copy(&op.owner.output)', 'if false && !copy(&op.owner.output)'),
    ('if !self.complete', 'if false'),
    ('clear_owned_region(&mut self.output)', 'clear_owned_region(&mut self.output[..0])'),
    ('.checked_sub(u64::try_from(bytes)', '.checked_add(u64::try_from(bytes)'),
    ('self.width != width || self.last != 8', 'false'),
    ('self.width > 1024', 'self.width > 2048'),
    ('if width > 1024 ||', 'if false ||'),
    ('self.last > 8', 'self.last > 9'),
    ('name != 0 || custom != 0', 'false'),
    ('op.owner.state.finish_setup()?;', 'let _ = op.owner.state.finish_setup();'),
)
WIRE_MUTANTS = (
    ('version != VERSION', 'false'),
    ('sequence == 0', 'false'),
    ('reserved != 0', 'false'),
    ('length > 1024', 'length > 2048'),
    ('last > 8', 'last > 9'),
    ('slot >= 8', 'slot > 8'),
    ('operation != BEGIN && budget != 0', 'false'),
    ('operation != START && (name != 0 || custom != 0)', 'false'),
    ('!planned && plan != [Slot::default(); 8]', 'false'),
    ('Owner::validate_plan(&plan)?;', 'let _ = plan;'),
    ('source.checked_add(length).ok_or(Error::Length)?;', 'let _ = source.wrapping_add(length);'),
    ('input.len() != self.length', 'false'),
    ('self.operation == NAME', 'self.operation == CUSTOM'),
)
HOST_MUTANTS = (
    ('self.sequence == 0', 'false'),
    ('self.slot >= 8', 'self.slot > 8'),
    ('self.op != 90 && self.budget != 0', 'false'),
    ('self.op != 91 && (self.name_bits != 0 || self.custom_bits != 0)', 'false'),
    ('self.op == 98', 'self.op == 97'),
)


def miri(directory, toolchain):
    dependencies = ''.join(name + '={path=' + json.dumps(str(base.ROOT / 'crates' / name)) + '}\n'
                           for name in ('brynja-core', 'brynja-hash-sha3'))
    for folder, package, entry, extra in (
        ('stream-fixture', 'sha3_stream', 'sha3_stream.rs', ''),
        ('fixture', 'enclave-sha3-batch-miri', 'sha3_batch.rs',
         'sha3_stream={path=' + json.dumps(str(directory / 'stream-fixture')) + '}\n'),
    ):
        fixture = directory / folder
        fixture.mkdir()
        (fixture / 'Cargo.toml').write_text('[package]\nname=' + json.dumps(package) +
            '\nversion="0.0.0"\nedition="2024"\n[lib]\npath=' + json.dumps(str(directory / entry)) +
            '\n[dependencies]\n' + dependencies + extra + '[workspace]\n')
    for test in ('cancellation_copy_failure_and_unwind_clear_retained_state',
                 'budgets_slots_setup_and_canonical_bits_fail_closed'):
        output = base.run(['cargo', '+' + toolchain, 'miri', 'test', '--offline',
                          '--manifest-path', str(directory / 'fixture/Cargo.toml'), '--lib', test])
        if '1 passed; 0 failed' not in output:
            raise AssertionError(output)
        print(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--miri-toolchain')
    parser.add_argument('--directory', type=Path, help='Retain isolated build products outside target/')
    args = parser.parse_args()
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    manager = (contextlib.nullcontext(args.directory) if args.directory else
               tempfile.TemporaryDirectory(prefix='enclave-sha3-batch-'))
    with manager as tmp:
        directory = Path(tmp).resolve()
        command, executable, count = builder.build(directory, target, testing=True)
        result = base.run([str(executable)])
        print(result)
        if '10 passed; 0 failed' not in result:
            raise AssertionError(result)
        for name, mutants in (('sha3_batch.rs', MUTANTS), ('sha3_batch_wire.rs', WIRE_MUTANTS), ('sha3_batch_host_wire.rs', HOST_MUTANTS)):
            path = directory / name
            original = path.read_text()
            for before, after in mutants:
                if original.count(before) != 1:
                    raise ValueError('Stale mutant ' + before)
                try:
                    path.write_text(original.replace(before, after))
                    base.run(command + ['-A', 'unused_variables'])
                    outcome = subprocess.run([str(executable)], capture_output=True, text=True, timeout=120)
                    if outcome.returncode == 0 or 'FAILED' not in outcome.stdout:
                        raise AssertionError('Mutant survived: ' + before)
                finally:
                    path.write_text(original)
        placement.check(directory, args.miri_toolchain)
        if args.miri_toolchain:
            miri(directory, args.miri_toolchain)
        # Retained products must contain the clean build, not the last mutant.
        base.run(command)
        result = base.run([str(executable)])
        if '10 passed; 0 failed' not in result:
            raise AssertionError(result)
        record = {
            'schema': 1, 'status': 'COMPONENT_TESTS_PASS',
            'native_enclave_execution': False, 'production_qualified': False,
            'tests': 10, 'independent_cases': count, 'activity_masks': 255,
            'compiled_mutants': len(MUTANTS) + len(WIRE_MUTANTS) + len(HOST_MUTANTS),
            'placement_mutants': 2, 'miri_toolchain': args.miri_toolchain,
            'clean_executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
            'initial_build_record_sha256': hashlib.sha256((directory / 'sha3-batch-build.json').read_bytes()).hexdigest(),
            'source_sha256': {str(p.relative_to(base.ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (Path(__file__), Path(placement.__file__),
                          base.SOURCE / 'sha3_batch_worker.rs', base.SOURCE / 'sha3_batch_placement_tests.rs')},
        }
        (directory / 'sha3-batch-tests.json').write_text(json.dumps(record, indent=2) + '\n')
    print(f'SHA-3 scalar batch: ten tests; {count} independent cases; 255 mixed activity masks; '
          f'{len(MUTANTS) + len(WIRE_MUTANTS) + len(HOST_MUTANTS)} compiled mutants rejected; no native qualification')


if __name__ == '__main__':
    main()
