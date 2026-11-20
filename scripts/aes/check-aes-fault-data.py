#!/usr/bin/env python3
"""Explicit source-data experiment; never a release or fault-qualification gate."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PREFIX = 'aes::fault_integrity::corruption_tests::'
FULL = 'every_retained_schedule_byte_replacement'
SMALL = (
    'mutation_families_and_invalid_sites_are_explicit',
    'persistent_schedule_changes_survive_repeated_calls_without_repair',
    'common_mode_wrong_input_and_wrong_key_are_negative_controls',
    'a_single_changed_input_replica_diverges_but_is_not_opaque_capture_evidence',
)
MARKER = ('SOURCE_DATA_ONLY: trials=638976 mismatch=636480 ineffective_correct=2496 '
          'wrong_agreement=0; one key/block per width/direction; '
          'no lifecycle, release or binary qualification')
SUMMARY = re.compile(r'^test result: ok\. (\d+) passed; (\d+) failed; '
                     r'(\d+) ignored; (\d+) measured; (\d+) filtered out; ', re.M)


def command(toolchain, full):
    if toolchain not in ('1.90.0', '1.99.1'):
        raise ValueError('unlisted toolchain')
    args = ['cargo', f'+{toolchain}', 'test', '--locked', '--release', '--lib',
            '-p', 'brynja-crypto', '--features', 'hazmat-aes-block',
            '--target-dir', str(ROOT / 'target' / f'aes-fault-data-{toolchain}'),
            PREFIX + (FULL if full else ''), '--', '--nocapture']
    if full:
        args += ['--ignored', '--exact']
    return args


def environment(source):
    result = dict(source)
    for name, value in source.items():
        if value and (name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC',
                              'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
                              'CARGO_BUILD_RUSTFLAGS') or
                      (name.startswith('CARGO_TARGET_') and name.endswith('_RUSTFLAGS'))):
            raise ValueError(f'clear overriding build environment: {name}')
    # Empty encoded flags also override RUSTFLAGS; remove both empty spellings.
    result.pop('CARGO_ENCODED_RUSTFLAGS', None)
    result['RUSTFLAGS'] = '--cfg brynja_fault_profile_research --cfg brynja_fault_evidence'
    result['CARGO_TERM_COLOR'] = 'never'
    return result


def validate_output(output, full):
    summaries = SUMMARY.findall(output)
    expected = ('1', '0', '0', '0') if full else ('4', '0', '1', '0')
    if len(summaries) != 1 or summaries[0][:4] != expected:
        raise ValueError('missing or unexpected test population (zero tests is not a pass)')
    selected = (FULL,) if full else SMALL
    for name in selected:
        if output.splitlines().count(f'test {PREFIX}{name} ... ok') != 1:
            raise ValueError(f'missing exact successful test: {name}')
    if full and output.splitlines().count(MARKER) != 1:
        raise ValueError('missing or changed source-data population marker')
    if not full and 'SOURCE_DATA_ONLY:' in output:
        raise ValueError('full campaign unexpectedly ran in the small-test phase')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=('1.90.0', '1.99.1'), default='1.99.1')
    args = parser.parse_args()
    try:
        env = environment(os.environ)
        for full in (False, True):
            completed = subprocess.run(command(args.toolchain, full), cwd=ROOT,
                                       env=env, text=True, capture_output=True,
                                       timeout=300, check=False)
            print(completed.stdout, end='')
            print(completed.stderr, end='', file=sys.stderr)
            if completed.returncode != 0:
                raise ValueError(f'cargo exited with {completed.returncode}')
            validate_output(completed.stdout, full)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f'AES source-data experiment failed: {error}', file=sys.stderr)
        return 2
    print('AES source-data experiment complete; NOT fault-profile qualification.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
