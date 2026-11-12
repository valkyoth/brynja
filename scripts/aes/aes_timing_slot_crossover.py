"""Strict class/slot crossover plumbing and diagnostics; no sampling on import."""
import math
import re
import statistics
import subprocess

SAMPLES, WARMUP, REPEAT = 8192, 256, 4
ORDER_SEED = 0x0273_c205_50fe_0001
CAMPAIGNS = ((192, 'decrypt-block', 22), (256, 'public-block', 37), (256, 'public-key', 36))
CONTROLS = ('values', 'identical')
TESTS = {'slot_crossover::tests::' + name for name in (
    'patterns_are_balanced_reproducible_and_campaign_separated',
    'every_pattern_visits_every_cell_once_with_correct_values',
    'slot_addresses_stay_fixed_when_classes_and_rounds_change',
    'identical_input_control_preserves_labels_but_equalizes_values',
    'invalid_patterns_do_not_call_the_operation',
    'every_failure_position_stops_without_retry_or_later_cells')}
TESTS |= {'crossover_driver::tests::' + name for name in (
    'malformed_phase_fails_before_authority', 'corpus_ids_match_original_campaigns',
    'address_drift_and_invalid_slots_fail')}


def require(ok, message):
    if not ok:
        raise ValueError('AES crossover: ' + message)


def patterns(campaign):
    state = ORDER_SEED ^ campaign
    mask = (1 << 64) - 1
    result = []
    for count in (WARMUP, SAMPLES):
        section = [i % 8 for i in range(count)]
        for end in range(count - 1, 0, -1):
            state = (state + 0x9e3779b97f4a7c15) & mask
            value = ((state ^ (state >> 30)) * 0xbf58476d1ce4e5b9) & mask
            value = ((value ^ (value >> 27)) * 0x94d049bb133111eb) & mask
            value ^= value >> 31
            chosen = value % (end + 1)
            section[end], section[chosen] = section[chosen], section[end]
        result.extend(section)
    return result


def cells(pattern):
    require(type(pattern) is int and 0 <= pattern < 8, 'invalid pattern')
    mapping = pattern & 1
    result = []
    for mapping, first in ((mapping, (pattern >> 1) & 1), (1 - mapping, (pattern >> 2) & 1)):
        for cls in (first, 1 - first):
            result.append((cls, cls ^ mapping))
    return result


def header(policy):
    require((policy.SAMPLES, policy.REPEAT, policy.WARMUP) == (SAMPLES, REPEAT, WARMUP), 'original policy changed')
    return f'AES_SLOT_CROSSOVER_POLICY {SAMPLES} {REPEAT} {WARMUP} {policy.SEED} {ORDER_SEED}'


def fixture(source, slots, driver):
    old = '    run(&args[0])\n'
    require(source.count(old) == 1, 'entry point changed')
    source = source.replace(old, '    if args[0].starts_with("crossover-") {\n'
                            '        crossover_driver::run(&args[0])\n'
                            '    } else { run(&args[0]) }\n')
    return source + '\nmod slot_crossover {\n' + slots + '\n}\nmod crossover_driver {\n' + driver + '\n}\n'


def check_tests(output, policy):
    names = re.findall(r'^test (\S+) \.\.\. ok$', output, re.M)
    summaries = re.findall(r'^test result:.*$', output, re.M)
    expected = TESTS | policy.TESTS
    require(len(names) == len(expected) and set(names) == expected and len(summaries) == 1
            and re.fullmatch(rf'test result: ok\. {len(expected)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in [0-9.]+s', summaries[0]),
            'missing/failed crossover tests')


def preflight(output, executable, env, policy):
    expected = [header(policy)]
    answers = {}
    for bits, mode, campaign in CAMPAIGNS:
        cases = list(policy.corpus(campaign))
        for control in CONTROLS:
            for sample in (0, SAMPLES // 2, SAMPLES - 1):
                for pattern in range(8):
                    for cls, slot in cells(pattern):
                        key, block = policy.inputs(cases[WARMUP + sample], bits, mode, 0 if control == 'identical' else cls)
                        identity = (bits, mode.startswith('decrypt-'), key, block)
                        if identity not in answers:
                            answer = subprocess.run([str(executable), 'enc', f'-aes-{bits}-ecb', '-nopad', '-nosalt',
                                                     '-K', key.hex(), '-d' if identity[1] else '-e'],
                                                    input=block, env=env, capture_output=True, timeout=15)
                            require(answer.returncode == 0 and not answer.stderr and len(answer.stdout) == 16, 'oracle failed')
                            answers[identity] = answer.stdout.hex()
                        expected.append(f'CROSS_VECTOR {bits} {mode} {control} {sample} {pattern} {cls} {slot} {answers[identity]}')
    require(output.splitlines() == expected + ['AES_SLOT_CROSSOVER_END crossover-preflight'], 'crossover oracle/cell/order mismatch')


def addresses(rows):
    require(len(rows) == 2 and all(len(x) == 2 for x in rows), 'address population')
    require(all(type(n) is int and 0 < n < 2**64 - 96 for row in rows for n in row), 'invalid address')
    require(rows[1][0] - rows[0][0] == 48 and rows[1][1] - rows[0][1] == 48, 'slot stride changed')
    regions = sorted((start, start + length) for row in rows for start, length in zip(row, (32, 16)))
    require(all(a[1] <= b[0] for a, b in zip(regions, regions[1:])), 'overlapping input regions')
    require(max(end for _, end in regions) - min(start for start, _ in regions) == 96, 'unexpected slot layout')


def describe(rows, policy):
    comparisons = {}
    for name, left, right in (('class_at_slot0', 0, 2), ('class_at_slot1', 1, 3),
                              ('slot_with_fixed', 0, 1), ('slot_with_random', 2, 3)):
        comparisons[name] = policy.screen([(row[left], row[right]) for row in rows])
    differences = [(a - c) - (b - d) for a, b, c, d in rows]
    delta = statistics.mean(differences)
    se = math.sqrt(statistics.variance(differences) / len(differences))
    return {'conditional_comparisons': comparisons,
            'interaction_fixed_minus_random_slot0_minus_slot1_ns': delta,
            'interaction_descriptive_signed_ratio': delta / se if se else None,
            'interaction_zero_standard_error': se == 0,
            'rounds': len(rows), 'cell_durations': len(rows) * 4}


def grouped_descriptions(rows, order):
    def group(selected):
        return {'rounds': len(selected),
                'cell_mean_ns': [statistics.mean(row[i] for row in selected) for i in range(4)]}
    return {'order_patterns': [{'pattern': pattern, **group([row for row, p in zip(rows, order) if p == pattern])}
                                for pattern in range(8)],
            'chronological_eighths': [group(rows[i:i + 1024]) for i in range(0, SAMPLES, 1024)]}


def parse(output, policy):
    lines = output.splitlines()
    require(len(lines) == 2 + len(CAMPAIGNS) * len(CONTROLS) * (2 + SAMPLES)
            and lines[0] == header(policy) and lines[-1] == 'AES_SLOT_CROSSOVER_END crossover-measure',
            'policy/population/completion mismatch')
    cursor, result = 1, []
    for bits, mode, campaign in CAMPAIGNS:
        order = patterns(campaign)[WARMUP:]
        for control in CONTROLS:
            locations = []
            for slot in (0, 1):
                fields = lines[cursor].split()
                cursor += 1
                require(len(fields) == 7 and fields[:5] == ['SLOT', str(bits), mode, control, str(slot)]
                        and all(re.fullmatch(r'[1-9][0-9]{0,19}', x) for x in fields[5:]), 'slot identity/addresses')
                locations.append(tuple(map(int, fields[5:])))
            addresses(locations)
            rows = []
            for sample, pattern in enumerate(order):
                fields = lines[cursor].split()
                cursor += 1
                require(len(fields) == 10 and fields[:6] == ['CROSS_SAMPLE', str(bits), mode, control, str(sample), str(pattern)]
                        and all(re.fullmatch(r'[1-9][0-9]{0,18}', x) for x in fields[6:]), 'sample identity/order/duration')
                rows.append(tuple(map(int, fields[6:])))
            result.append({'bits': bits, 'mode': mode, 'control': control,
                           'input_addresses': locations, **describe(rows, policy), **grouped_descriptions(rows, order)})
    return {'scope': 'Crossover diagnostics only; no retrospective or constant-time acceptance', 'campaigns': result}


def validate_preflight(result, executable, env, kernel, payload, policy):
    require(type(result.returncode) is int and result.returncode == 0 and not result.stderr, 'failed or diagnostic-bearing preflight')
    preflight(payload(result.stdout, kernel), executable, env, policy)
