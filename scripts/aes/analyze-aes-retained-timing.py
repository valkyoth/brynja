#!/usr/bin/env python3
"""Offline descriptive diagnostics of retained ARM alarms; never timing acceptance."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import statistics

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
spec = importlib.util.spec_from_file_location('retained_timing_policy', HERE / 'check-aes-fixed-random.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
RECORDS = ROOT / 'assurance/aes-native-observations/v0.27.3'
NOTICE = ('Exploratory post-observation diagnostics, not a new acceptance test. '
          'All samples and original alarms/noise retained; no causal attribution, '
          'multiple-testing correction, independence guarantee or timing pass.')
BLOCKS = (64, 256, 1024)
LAGS = (1, 8, 64)


def mean(values):
    return statistics.mean(values) if values else None


def lag_correlation(values, lag):
    """Pearson correlation of the two overlapping lagged sequences."""
    if not 0 < lag < len(values):
        raise ValueError('lag must be inside the series')
    left, right = values[:-lag], values[lag:]
    lm, rm = mean(left), mean(right)
    covariance = sum((a - lm) * (b - rm) for a, b in zip(left, right))
    denominator = math.sqrt(sum((a - lm)**2 for a in left) * sum((b - rm)**2 for b in right))
    return covariance / denominator if denominator else None


def block_summary(values, size):
    if size <= 0 or len(values) % size or len(values) // size < 2:
        raise ValueError('complete population must divide into at least two blocks')
    means = [mean(values[i:i + size]) for i in range(0, len(values), size)]
    delta = mean(means)
    se = math.sqrt(statistics.variance(means) / len(means))
    return {'pairs_per_block': size, 'blocks': len(means),
            'mean_difference_ns': delta, 'standard_error_of_block_means_ns': se,
            'descriptive_signed_ratio': delta / se if se else None,
            'zero_standard_error': se == 0,
            'positive_blocks': sum(x > 0 for x in means),
            'negative_blocks': sum(x < 0 for x in means),
            'zero_blocks': sum(x == 0 for x in means),
            'minimum_block_mean_ns': min(means), 'maximum_block_mean_ns': max(means)}


def describe(samples):
    """Rows are (first class, fixed ns, random ns), already policy-validated."""
    if len(samples) != policy.SAMPLES or any(first not in (0, 1) for first, _, _ in samples):
        raise ValueError('wrong descriptive population')
    differences = [a - b for _, a, b in samples]
    ordered = []
    for first in (0, 1):
        selected = [a - b for f, a, b in samples if f == first]
        ordered.append({'first_class': first, 'pairs': len(selected), 'mean_difference_ns': mean(selected)})
    transitions = []
    # The first retained pair has no retained predecessor. It remains in every
    # full-population statistic; only this explicitly counted diagnostic omits it.
    for previous in (0, 1):
        for current in (0, 1):
            selected = [a - b for prior, (first, a, b) in zip(samples, samples[1:])
                        if prior[0] == previous and first == current]
            transitions.append({'previous_first': previous, 'current_first': current,
                                'pairs': len(selected), 'mean_difference_ns': mean(selected)})
    return {'pairs': len(samples), 'mean_difference_ns': mean(differences),
            'order_strata': ordered, 'order_transitions': transitions,
            'chronological_eighth_means_ns': [mean(differences[i:i + 1024])
                                             for i in range(0, len(samples), 1024)],
            'difference_lag_correlations': {str(lag): lag_correlation(differences, lag) for lag in LAGS},
            'block_descriptions': [block_summary(differences, size) for size in BLOCKS],
            'duration_modes_ns_and_counts': [Counter(row[column] for row in samples).most_common(6)
                                            for column in (1, 2)]}


def load_measure(path, expected_hash, control):
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError('measurement exceeds bounded input size')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError('retained measurement hash mismatch')
    data = json.loads(raw)
    if type(data.get('returncode')) is not int or data['returncode'] != 0 or data.get('stderr') != '':
        raise ValueError('incomplete or diagnostic-bearing measurement')
    header, separator, payload = data['stdout'].partition('\n')
    if not separator or header != 'AES_FORCED_AUTHORITY: ArmAes':
        raise ValueError('missing ARM authority marker')
    if control is not None:
        header, separator, payload = payload.partition('\n')
        if not separator or header != 'AES_TIMING_CONTROL: ' + control:
            raise ValueError('wrong control marker')
    verdicts = policy.parse(payload)  # Exact original population/order/numeric checks.
    lines = payload.splitlines()[1:-1]
    diagnostics = []
    for index, verdict in enumerate(verdicts):
        rows = [tuple(map(int, line.split()[5:]))
                for line in lines[index * policy.SAMPLES:(index + 1) * policy.SAMPLES]]
        diagnostics.append({'original_verdict': verdict, **describe(rows)})
    return verdicts, diagnostics


def analyze():
    observations = []
    for filename in ('integrated-fixed-random-20261110.json', 'timing-address-controls-20261110.json'):
        source = RECORDS / filename
        raw = source.read_bytes()
        records = json.loads(raw)['records']
        for record in records:
            original = record['name'].startswith('aws-arm-integrated-')
            address = record['name'] == 'aws-arm-address-controls-current-20261110'
            if not (original or address):
                continue
            control = None if original else 'separate-values'
            saved = record if original else next(x for x in record['controls'] if x['control'] == control)
            directory = ROOT / record['directory']
            if control:
                directory /= control
            expected_hash = saved['files_sha256']['measure.json']
            verdicts, diagnostics = load_measure(directory / 'measure.json', expected_hash, control)
            summary = {'campaigns': verdicts, 'alarms': sum(x['alarm'] for x in verdicts),
                       'inconclusive': sum(x['inconclusive'] for x in verdicts)}
            if summary != saved['summary']:
                raise ValueError('original summary replay mismatch')
            observations.append({'name': record['name'], 'control': control,
                                 'source_record': str(source.relative_to(ROOT)),
                                 'source_record_sha256': hashlib.sha256(raw).hexdigest(),
                                 'measurement_sha256': expected_hash, 'campaigns': diagnostics})
    if len(observations) != 3:
        raise ValueError('expected exactly three retained ARM observations')
    return {'notice': NOTICE, 'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'policy_sha256': hashlib.sha256((HERE / 'check-aes-fixed-random.py').read_bytes()).hexdigest(),
            'observations': observations}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Create a new diagnostic JSON; never overwrite an existing record')
    args = parser.parse_args()
    try:
        result = json.dumps(analyze(), indent=2, allow_nan=False) + '\n'
        if args.output:
            with args.output.open('x') as destination:
                destination.write(result)
        else:
            print(result, end='')
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(2, f'Retained timing analysis failed: {error}\n')


if __name__ == '__main__':
    main()
