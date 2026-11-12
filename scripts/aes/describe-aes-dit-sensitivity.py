#!/usr/bin/env python3
"""Post-collection descriptions only: no measurements, new verdicts or power claim."""
import argparse
import importlib.util
import json
import math
from pathlib import Path
import statistics

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('dit_description_analysis', HERE / 'analyze-aes-dit-finite.py')
analysis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analysis)
policy = analysis.policy
require = analysis.require


def describe(pairs):
    require(len(pairs) == policy.SAMPLES and all(len(p) == 2 for p in pairs)
            and all(type(x) is int and 0 < x < 10**19 for p in pairs for x in p),
            'invalid descriptive population')
    left, right = zip(*pairs)
    differences = [a - b for a, b in pairs]
    welch_se = math.sqrt((statistics.variance(left) + statistics.variance(right)) / len(pairs))
    paired_se = math.sqrt(statistics.variance(differences) / len(pairs))
    trim = len(pairs) // 100

    def trimmed(values):
        return statistics.mean(sorted(values)[trim:len(values) - trim])

    return {'pairs': len(pairs), 'welch_standard_error_ns': welch_se,
            'paired_standard_error_ns': paired_se,
            'welch_observed_cutoff_scale_ns': policy.LIMIT * welch_se,
            'paired_observed_cutoff_scale_ns': policy.LIMIT * paired_se,
            'degenerate_standard_error': welch_se == 0 or paired_se == 0,
            'untrimmed_difference_ns': statistics.mean(differences),
            'posthoc_trim_each_tail_count': trim,
            'posthoc_trimmed_class_mean_difference_ns': trimmed(left) - trimmed(right),
            'posthoc_trimmed_paired_difference_ns': trimmed(differences)}


def describe_run(directory, row):
    name, control = row['launch'], row['control']
    require(analysis.worker.digest(directory / (name + '.json')) == row['record_sha256'],
            'original process record changed')
    checked = analysis.measurement(directory, name, row['command'], control)
    require(checked == {k: v for k, v in row.items()
                       if k not in ('launch', 'round', 'compiler', 'control', 'role')},
            'frozen summary does not reproduce')
    raw_path = directory / (name + '.stdout')
    raw = analysis.read(raw_path, 64 * 1024 * 1024)
    require(analysis.worker.digest(raw_path) == row['stdout_sha256'], 'raw sample hash changed')
    lines = raw.decode('utf-8').splitlines()[3:-1]  # Strict parser above validated headers/order.
    require(len(lines) == len(policy.CAMPAIGNS) * policy.SAMPLES, 'wrong population')
    campaigns = []
    for i, (bits, owner, mode) in enumerate(policy.CAMPAIGNS):
        pairs = [tuple(map(int, line.split()[-2:]))
                 for line in lines[i * policy.SAMPLES:(i + 1) * policy.SAMPLES]]
        campaigns.append({'bits': bits, 'owner': owner, 'mode': mode, **describe(pairs)})
    return {k: row[k] for k in ('launch', 'compiler', 'control', 'round', 'stdout_sha256')} | {'campaigns': campaigns}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('record', type=Path)
    parser.add_argument('sha256')
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    require(analysis.worker.digest(args.record) == args.sha256, 'frozen results hash mismatch')
    original = json.loads(analysis.read(args.record, 2 * 1024 * 1024))
    require(len(original['launches']) == 32 and not any('validation_error' in r for r in original['launches']),
            'incomplete/invalid original screen')
    rows = [describe_run(args.directory, row) for row in original['launches']]
    summaries = []
    for owner in ('cached', 'ephemeral', 'cached-import'):
        selected = [r for launch in rows if launch['control'] == 'shared-values'
                    for r in launch['campaigns'] if r['owner'] == owner]
        summaries.append({'owner': owner, 'campaign_observations': len(selected),
                          **{field: statistics.median(r[field] for r in selected) for field in
                             ('welch_observed_cutoff_scale_ns', 'paired_observed_cutoff_scale_ns')}})
    output = {'schema': 1, 'original_results_sha256': args.sha256,
              'notice': 'Post-observation descriptive scales, not a minimum detectable effect, power bound or acceptance rule. Trimmed summaries never alter the frozen verdict.',
              'shared_values_medians': summaries, 'launches': rows}
    analysis.worker.write(args.output, output)
    print(json.dumps(summaries, indent=2))


if __name__ == '__main__':
    main()
