#!/usr/bin/env python3
"""Synthetic native evidence and ASan no-skip regressions; no qualification claim."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import mock_open, patch
import hardened_native_evidence as evidence
import hardened_native_host as host


def rejected(function):
    try:
        function()
    except (ValueError, OSError):
        return
    raise AssertionError('invalid native assurance accepted')


def artifact(lane, commit, sources):
    target, kernels = evidence.LANES[lane]
    summary = 'SHA-2 hardened execution acceptance: PASS; named=240; general=4590\n'
    results = {'portable': summary + 'narrow=Portable; wide=Portable\n',
               'kernel_tests': '\n'.join('HARDENED_KERNEL_EXECUTION: ' + k + '; blocks=512' for k in kernels) + '\ntest result: ok. 2 passed\n'}
    for mode in ('static', *(['hosted'] if len(kernels) == 2 else [])):
        kind = 'Static' if mode == 'static' else 'Runtime'
        wide = kind + '(ArmSha512)' if len(kernels) == 2 else 'Portable'
        results[mode] = summary + 'narrow=' + kind + '(' + kernels[0] + '); wide=' + wide + '\n'
    return {'schema': 1, 'capture_commit': commit, 'lane': lane, 'target': target,
            'cpu': 'synthetic CPU', 'os': 'synthetic OS',
            'compiler': 'rustc 1.98.1 (fixture)\nhost: ' + target + '\nrelease: 1.98.1\n',
            'sources': sources, 'kernels': kernels, 'results': results,
            'native_attestation': 'operator asserts native, not QEMU'}


def evidence_tests():
    commit, head = '1' * 40, '2' * 40
    source = b'synthetic source\n'
    sources = {'source.rs': hashlib.sha256(source).hexdigest()}
    cases = 0
    for lane in evidence.LANES:
        original = artifact(lane, commit, sources)
        evidence.validate_record(original, lane, commit, sources)
        mutations = [('capture_commit', head), ('target', 'wrong'), ('cpu', ''),
                     ('os', ''), ('compiler', 'rustc 1.90.0'), ('sources', {}),
                     ('kernels', []), ('native_attestation', 'QEMU'), ('schema', True)]
        for key, value in mutations:
            broken = copy.deepcopy(original)
            broken[key] = value
            rejected(lambda: evidence.validate_record(broken, lane, commit, sources))
            cases += 1
        for mode in original['results']:
            broken = copy.deepcopy(original)
            broken['results'][mode] = 'test result: ok. 0 passed'
            rejected(lambda: evidence.validate_record(broken, lane, commit, sources))
            cases += 1
    with tempfile.TemporaryDirectory(prefix='brynja-native-test-') as directory:
        root = Path(directory)
        (root / 'security').mkdir()
        (root / 'assurance/sha2-hardened-native').mkdir(parents=True)
        index = {'schema': 1, 'capture_commit': commit, 'lanes': {}}
        for lane in evidence.LANES:
            name = 'assurance/sha2-hardened-native/' + lane + '.json'
            raw = (json.dumps(artifact(lane, commit, sources), sort_keys=True) + '\n').encode()
            (root / name).write_bytes(raw)
            index['lanes'][lane] = {'artifact': name, 'sha256': hashlib.sha256(raw).hexdigest(),
                                    'cpu': 'synthetic CPU', 'reviewed': True}

        def git(_root, *args):
            if args == ('rev-parse', 'HEAD'):
                return head.encode()
            if args[0] in ('status', 'merge-base'):
                return b''
            if args[0] == 'cat-file':
                if args[-1].startswith(head + ':'):
                    return str((root / args[-1].split(':', 1)[1]).stat().st_size).encode()
                return str(len(source)).encode()
            if args[0] == 'show':
                if args[-1].startswith(head + ':'):
                    return (root / args[-1].split(':', 1)[1]).read_bytes()
                return source
            raise AssertionError(args)

        def run(value):
            (root / evidence.INDEX).write_text(json.dumps(value))
            evidence.validate(root, head)

        with patch.object(evidence, 'git', side_effect=git), patch.object(evidence, 'sources', return_value=sources):
            run(index)  # Later evidence/report-only HEAD is allowed.
            for change in ('missing', 'pending', 'unreviewed', 'hash', 'cpu', 'path'):
                broken = copy.deepcopy(index)
                row = broken['lanes']['linux-x86_64']
                if change == 'missing':
                    broken['lanes'].pop('linux-aarch64')
                elif change == 'pending':
                    broken['capture_commit'] = None
                else:
                    key, value = {'unreviewed': ('reviewed', False), 'hash': ('sha256', '0' * 64),
                                  'cpu': ('cpu', 'different CPU'), 'path': ('artifact', '../escape')}[change]
                    row[key] = value
                rejected(lambda: run(broken))
                cases += 1
            (root / evidence.INDEX).write_text(json.dumps(index))
            rejected(lambda: evidence.validate(root, commit))
            with patch.object(evidence, 'sources', return_value={'source.rs': '0' * 64}):
                rejected(lambda: run(index))
            with patch.object(evidence, 'git', side_effect=lambda r, *a: b'dirty' if a[0] == 'status' else git(r, *a)):
                rejected(lambda: run(index))
            for name in (evidence.INDEX, index['lanes']['linux-x86_64']['artifact']):
                with patch.object(evidence, 'git', side_effect=lambda r, *a: b'not the committed content' if
                                  a == ('show', head + ':' + name) else git(r, *a)):
                    rejected(lambda: run(index))
                cases += 1
        rejected(lambda: evidence.document(b'{"schema":1,"schema":1}'))
    print(f'Native evidence rejects {cases + 4} identity, source, lane, review and result regressions')


def asan_tests():
    good = 'model name : fixture CPU\nflags : sha_ni sse2\n'
    assert host.x86_cpuinfo(good) == 'fixture CPU'
    for value in ('', good.replace('sha_ni', ''), good + 'flags : sse2\n'):
        rejected(lambda: host.x86_cpuinfo(value))
    for value in ('', 'test result: ok. 0 passed', host.MARKER):
        rejected(lambda: host.validate_asan(value))
    host.validate_asan(host.MARKER + '\ntest result: ok. 2 passed\n')
    spec = importlib.util.spec_from_file_location('asan_capture', Path(__file__).with_name('check-sha2-hardened-asan.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with patch.object(host, 'clean_environment', return_value={}), patch.object(host, 'execute') as execute:
        with patch.object(host, 'x86_host', side_effect=ValueError('missing SHA')):
            rejected(module.main)
            execute.assert_not_called()
        with patch.object(host, 'x86_host', return_value='fixture CPU'):
            execute.return_value = host.MARKER + '\ntest result: ok. 2 passed\n'
            module.main()
            command, env = execute.call_args.args
            assert command == host.asan_command()
            assert env['RUSTFLAGS'] == '-Zsanitizer=address -C target-feature=+sha,+sse2'
            execute.return_value = 'test result: ok. 0 passed'
            rejected(module.main)
    for name in ('RUSTFLAGS', 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER', 'ASAN_OPTIONS'):
        with patch.dict(os.environ, {name: 'override'}, clear=True):
            rejected(host.clean_environment)
    print('ASan rejects unsupported CPUs, missing execution and inherited overrides')


def capture_tests():
    spec = importlib.util.spec_from_file_location('native_capture', Path(__file__).with_name('capture-sha2-hardened-native.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    commit, sources = '1' * 40, {'source.rs': '0' * 64}
    record = artifact('apple-aarch64', commit, sources)
    calls = []

    def execute(command, env):
        calls.append((command, env))
        if command[0] == 'rustc':
            return record['compiler']
        if command[0] == 'sysctl':
            return 'Apple synthetic CPU\n'
        if 'test' in command:
            return record['results']['kernel_tests']
        return record['results'][command[-1]]

    with tempfile.TemporaryDirectory(prefix='brynja-capture-test-') as directory:
        output = Path(directory) / 'capture.json'
        with patch.object(module.platform, 'system', return_value='Darwin'), \
                patch.object(module.platform, 'machine', return_value='arm64'), \
                patch.object(host, 'clean_environment', return_value={}), \
                patch.object(host, 'execute', side_effect=execute), \
                patch.object(evidence, 'sources', return_value=sources), \
                patch.object(evidence, 'git', side_effect=lambda r, *a: commit.encode() if a[0] == 'rev-parse' else b''):
            module.capture('apple-aarch64', output)
            evidence.validate_record(evidence.document(output.read_bytes()), 'apple-aarch64', commit, sources)
            assert next(env for command, env in calls if command[-1] == 'static')['RUSTFLAGS'] == '-C target-feature=+neon,+sha2,+sha3'
            assert 'RUSTFLAGS' not in next(env for command, env in calls if command[-1] == 'hosted')
            record['results']['hosted'] = record['results']['portable']
            calls.clear()
            rejected(lambda: module.capture('apple-aarch64', Path(directory) / 'bad.json'))
            assert not any('RUSTFLAGS' in env for _, env in calls)
            assert not (Path(directory) / 'bad.json').exists()
    # Linux /proc/cpuinfo separates fields with tabs. Normalize identity only;
    # the artifact validator must continue rejecting embedded control bytes.
    record = artifact('linux-aarch64', commit, sources)
    cpuinfo = ('CPU implementer\t: 0x41\nCPU architecture: 8\n'
               'CPU part\t: 0xd40\nCPU revision\t: 1\n'
               'CPU part\t: 0xd40\nSerial\t: private-serial\n')
    with tempfile.TemporaryDirectory(prefix='brynja-linux-capture-test-') as directory:
        output = Path(directory) / 'capture.json'
        real_open = Path.open

        def open_cpu(path, *args, **kwargs):
            if str(path) == '/proc/cpuinfo':
                return mock_open(read_data=cpuinfo)()
            return real_open(path, *args, **kwargs)

        with patch.object(module.platform, 'system', return_value='Linux'), \
                patch.object(module.platform, 'machine', return_value='aarch64'), \
                patch.object(Path, 'open', open_cpu), \
                patch.object(host, 'clean_environment', return_value={}), \
                patch.object(host, 'execute', side_effect=execute), \
                patch.object(evidence, 'sources', return_value=sources), \
                patch.object(evidence, 'git', side_effect=lambda r, *a: commit.encode() if a[0] == 'rev-parse' else b''):
            module.capture('linux-aarch64', output)
            captured = evidence.document(output.read_bytes())
            assert captured['cpu'] == 'CPU architecture: 8; CPU implementer : 0x41; CPU part : 0xd40; CPU revision : 1'
            evidence.validate_record(captured, 'linux-aarch64', commit, sources)
            captured['cpu'] += '\t'
            rejected(lambda: evidence.validate_record(captured, 'linux-aarch64', commit, sources))
    # Facade version-only churn does not hide a changed selected dependency.
    raw = (evidence.ROOT / 'Cargo.lock').read_bytes()
    import tomllib
    version = next(row['version'] for row in tomllib.loads(raw.decode())['package'] if row['name'] == 'brynja')
    original = evidence.source_digest('Cargo.lock', raw)
    facade = raw.replace(('name = "brynja"\nversion = "' + version + '"').encode(), b'name = "brynja"\nversion = "999.0.0"')
    assert evidence.source_digest('Cargo.lock', facade) == original
    assert evidence.source_digest('Cargo.lock', raw.replace(b'name = "brynja-core"\nversion = "0.9.0"', b'name = "brynja-core"\nversion = "0.9.1"')) != original
    print('Capture enforces native host/compiler, preflight-before-static and selected lock identity')


if __name__ == '__main__':
    evidence_tests()
    asan_tests()
    capture_tests()
