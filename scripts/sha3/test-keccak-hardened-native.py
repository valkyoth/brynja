#!/usr/bin/env python3
"""Reject fabricated, incomplete, misbound and cross-lane native records."""
import copy
import keccak_hardened_native as evidence


def record(lane):
    target, kernel = evidence.LANES[lane]
    package = '\n'.join((
        'Packaged hardened Keccak public API: PASS',
        'Hardened Keccak packaged ownership rejects 54 bypasses',
        'Hardened Keccak packaged accelerated byte/bit/lifecycle tests: PASS',
        *(['Hardened Keccak hosted Arm execution: PASS; kernel=ArmKeccak'] if kernel == 'ArmKeccak' else [])))
    return {'schema': 1, 'commit': 'a' * 40, 'lane': lane, 'target': target, 'kernel': kernel,
            'cpu': 'test-only synthetic CPU', 'os': 'test-only OS',
            'compiler': 'rustc 1.98.1 (test)\nhost: ' + target + '\nrelease: 1.98.1\n',
            'sources': {'test-only.rs': 'b' * 64}, 'native_attestation': 'operator asserts native, not QEMU',
            'results': {'package': package, 'kernel_tests':
                'HARDENED_KECCAK_EXECUTION: ' + kernel + '; permutations=1024\n'
                'test result: ok. 4 passed; 0 failed\n'}}


def main():
    count = 0
    for lane in evidence.LANES:
        original = record(lane)
        check = lambda value: evidence.record_check(value, lane, 'a' * 40, {'test-only.rs': 'b' * 64})
        check(original)
        mutants = []
        for key in original:
            changed = copy.deepcopy(original)
            del changed[key]
            mutants.append(changed)
        for key, value in (('schema', True), ('commit', 'c' * 40), ('lane', 'other'),
                           ('target', 'wasm32-unknown-unknown'), ('kernel', 'X86Sha256'),
                           ('sources', {}), ('cpu', ''), ('cpu', 'host\nspoof'),
                           ('os', []), ('native_attestation', 'QEMU'), ('compiler', 'rustc 1.90.0')):
            changed = copy.deepcopy(original)
            changed[key] = value
            mutants.append(changed)
        for output in original['results']:
            for line in original['results'][output].splitlines():
                changed = copy.deepcopy(original)
                changed['results'][output] = changed['results'][output].replace(line, 'omitted')
                mutants.append(changed)
        for changed in mutants:
            try:
                check(changed)
            except ValueError:
                count += 1
                continue
            raise AssertionError('native record mutant escaped')
    try:
        evidence.shared.document(b'{"schema":1,"schema":1}')
    except ValueError:
        count += 1
    else:
        raise AssertionError('duplicate JSON accepted')
    gate = (evidence.ROOT / 'scripts/tag_gate.sh').read_text()
    assert '\npython3 scripts/sha3/check-keccak-hardened-native.py\n' in gate
    print(f'Hardened Keccak native schema/identity/source/results rejects {count} regressions')


if __name__ == '__main__':
    main()
