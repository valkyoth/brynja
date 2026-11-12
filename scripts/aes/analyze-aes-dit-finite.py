#!/usr/bin/env python3
"""Strict offline summary of a frozen finite DIT screen; never collect or retry."""
import argparse
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


worker = module('dit_finite_worker', 'collect-aes-dit-finite.py')
policy = module('dit_finite_policy', 'check-aes-fixed-random.py')
controls = module('dit_finite_controls', 'aes_timing_controls.py')
require = worker.require


def read(path, limit=1024 * 1024):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit,
            'missing/symlinked/oversized retained file: ' + str(path))
    return path.read_bytes()


def measurement(directory, name, command, control):
    record_path = directory / (name + '.json')
    record = json.loads(read(record_path))
    require(record['command'] == command, 'wrong retained command')
    require(type(record['returncode']) is int and record['returncode'] == 0
            and record['error'] is None, 'failed/incomplete process')
    stdout_path, stderr_path = (directory / (name + ext) for ext in ('.stdout', '.stderr'))
    raw = read(stdout_path, 64 * 1024 * 1024)
    stderr = read(stderr_path)
    require(worker.digest(stdout_path) == record['stdout_sha256']
            and worker.digest(stderr_path) == record['stderr_sha256'], 'retained output hash mismatch')
    require(not stderr, 'unexpected process diagnostics')
    text = raw.decode('utf-8')
    if control is None:
        require(text == 'AES_DIT_HOST_BUNDLE_PASS\n', 'invalid capability marker')
        return {**record, 'record_sha256': worker.digest(record_path)}
    first, separator, rest = text.partition('\n')
    require(separator and first == 'AES_FORCED_AUTHORITY: ArmAes', 'wrong authority marker')
    rows = policy.parse(controls.payload(rest, control))
    return {**record, 'record_sha256': worker.digest(record_path), 'campaigns': rows,
            'alarms': sum(row['alarm'] for row in rows),
            'inconclusive': sum(row['inconclusive'] for row in rows)}


def analyze(directory, declaration, expected):
    require(worker.digest(declaration) == expected, 'declaration hash mismatch')
    plan = json.loads(read(declaration))
    for key, filename in (('collector_sha256', 'collect-aes-dit-finite.py'),
                          ('timing_parser_sha256', 'check-aes-fixed-random.py'),
                          ('controls_parser_sha256', 'aes_timing_controls.py')):
        require(worker.digest(HERE / filename) == plan[key], 'frozen tool changed')
    require(json.loads(read(directory / 'declaration.json')) == plan, 'collector declaration differs')
    host = json.loads(read(directory / 'host.json'))
    require(host['declaration_sha256'] == expected and host['environment'] == worker.ENV,
            'wrong host declaration/environment')
    require(host['uname'][0] == plan['system'] and host['uname'][4] == plan['machine'], 'wrong host')
    complete = json.loads(read(directory / 'complete.json'))
    require(type(complete['launches']) is int and complete['launches'] == 32, 'incomplete collection')
    result = {'schema': 1, 'declaration_sha256': expected, 'host': host,
              'complete': complete, 'complete_sha256': worker.digest(directory / 'complete.json'),
              'host_sha256': worker.digest(directory / 'host.json'), 'probes': {}, 'launches': [],
              'screen_passed': True, 'notice': 'Scoped finite screen, not constant-time proof. Separate arms are diagnostics, not passes.'}
    for compiler in worker.COMPILERS:
        entry = plan['binaries'][compiler]
        result['probes'][compiler] = measurement(directory, 'probe-' + compiler, [entry['probe']], None)
    expected_names = {'probe-' + c for c in worker.COMPILERS}
    for index, (round_, compiler, control) in enumerate(worker.launches(), 1):
        name = f'{index:02d}-round{round_}-{compiler}-{control}'
        expected_names.add(name)
        row = {'launch': name, 'round': round_, 'compiler': compiler, 'control': control,
               'role': 'required-screen' if control.startswith('shared-') else 'address-diagnostic-not-pass'}
        try:
            row.update(measurement(directory, name, [plan['binaries'][compiler]['binary'], 'measure', control], control))
            if row['role'] == 'required-screen' and (row['alarms'] or row['inconclusive']):
                result['screen_passed'] = False
        except (ValueError, OSError, KeyError, TypeError) as exc:
            row['validation_error'] = str(exc)
            result['screen_passed'] = False
        result['launches'].append(row)
    require({p.stem for p in directory.glob('*.stdout')} == expected_names, 'missing/extra process outputs')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('declaration', type=Path)
    parser.add_argument('sha256')
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = analyze(args.directory, args.declaration, args.sha256)
    worker.write(args.output, result)
    for control in worker.CONTROLS:
        rows = [x for x in result['launches'] if x['control'] == control]
        print(json.dumps({'control': control, 'launches': len(rows),
                          'validation_errors': sum('validation_error' in x for x in rows),
                          'alarms': sum(x.get('alarms', 0) for x in rows),
                          'inconclusive': sum(x.get('inconclusive', 0) for x in rows)}))
    print('Scoped finite screen passed: ' + str(result['screen_passed']))


if __name__ == '__main__':
    main()
