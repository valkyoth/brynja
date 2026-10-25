"""Author diagnostic reconciliation; never native approval or runner attestation.

An explicit source anchor checks recorded bytes, not who executed them. A later
matching anchor does not turn a dirty capture into a clean capture at that commit.
No release gate imports this module or accepts its report as a receipt.
"""
import copy
import hashlib
import json
from pathlib import PurePosixPath
import re
import tomllib

import legacy_hmac_timing as timing

MANIFESTS = {'Cargo.toml', 'crates/brynja-legacy-hmac/Cargo.toml'}
FIELDS = set('schema kind claim measurement_scope route family host machine head sources_sha256 '
             'compiler compiler_binary_sha256 binary_sha256 build_command build_rustflags '
             'generic_host_probe command exit_status raw_stderr raw_output output_sha256 '
             'failure campaigns signals samples_per_class repetitions alarm_threshold'.split())


def require(condition, message):
    if not condition:
        raise ValueError('legacy timing reconciliation: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(raw):
    require(len(raw) <= 2 * 1024 * 1024, 'oversized observation')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def constant(_value):
        raise ValueError('nonfinite observation number')
    document = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    require(isinstance(document, dict) and set(document) == FIELDS, 'observation schema')
    return document


def workspace_move(before, after):
    """Only the observed direct-to-workspace dependency declaration migration.

    This is a diagnostic explanation, not a general manifest-reuse exemption.
    Versions, paths, default features, every other table and all lock bytes stay
    bound. Other manifest changes require a separate review/new observation.
    """
    old_root, new_root = [tomllib.loads(data['Cargo.toml'].decode()) for data in (before, after)]
    old_leaf, new_leaf = [tomllib.loads(data['crates/brynja-legacy-hmac/Cargo.toml'].decode())
                          for data in (before, after)]
    normalized_root, normalized_leaf = copy.deepcopy(new_root), copy.deepcopy(new_leaf)
    for name in ('brynja-legacy-md5', 'brynja-legacy-sha1'):
        require(name not in old_root['workspace']['dependencies'], 'not the reviewed workspace addition')
        require(normalized_root['workspace']['dependencies'].pop(name, None) == {
            'path': 'crates/' + name, 'version': '=0.1.0', 'default-features': False}, 'workspace dependency differs')
        require(old_leaf['dependencies'][name] == {
            'path': '../' + name, 'version': '=0.1.0', 'default-features': False}, 'original dependency differs')
        require(new_leaf['dependencies'][name] == {'workspace': True, 'default-features': False},
                'inherited dependency differs')
        normalized_leaf['dependencies'][name] = old_leaf['dependencies'][name]
    require(normalized_root == old_root and normalized_leaf == old_leaf, 'other manifest semantics changed')


def validate(document, route, family, target, current, anchor, captured_head):
    require(set(document) == FIELDS and type(document['schema']) is int and document['schema'] == 1,
            'schema identity')
    require(document['kind'] == 'author-operated-legacy-hmac-timing-observation', 'observation kind')
    require((document['route'], document['family']) == (route, family), 'route/family identity')
    arch = 'aarch64' if target == 'aarch64-apple-darwin' else 'x86_64'
    require(target in ('aarch64-apple-darwin', 'x86_64-unknown-linux-gnu'), 'unreviewed target')
    require(document['machine'] == arch and isinstance(document['host'], str)
            and document['host'].startswith('macOS-' if arch == 'aarch64' else 'Linux-'), 'host identity')
    require(route in (('portable', 'static', 'macos-resident', 'macos-compiled') if arch == 'aarch64'
                      else ('portable', 'static', 'linux-protected', 'linux-compiled')), 'host/route mismatch')
    compiler = document['compiler'].splitlines()
    require(len(compiler) == 7 and compiler[0].startswith('rustc 1.99.1 ')
            and compiler[4] == 'host: ' + target and compiler[5] == 'release: 1.99.1', 'compiler identity')
    require(type(document['exit_status']) is int and document['exit_status'] == 0
            and document['failure'] is None and document['raw_stderr'] == '', 'failed capture')
    for key in ('output_sha256', 'binary_sha256', 'compiler_binary_sha256'):
        require(isinstance(document[key], str) and re.fullmatch('[0-9a-f]{64}', document[key]), 'digest syntax')
    require(isinstance(document['head'], str) and re.fullmatch('[0-9a-f]{40}', document['head']), 'capture HEAD syntax')
    require(sha(document['raw_output'].encode()) == document['output_sha256'], 'raw output changed')
    require(type(document['samples_per_class']) is int and document['samples_per_class'] == timing.SAMPLES
            and type(document['repetitions']) is int and document['repetitions'] == timing.REPEAT
            and type(document['alarm_threshold']) in (int, float) and document['alarm_threshold'] == timing.LIMIT,
            'measurement settings changed')
    rows = timing.parse(document['raw_output'], route, family, arch)
    require(rows == document['campaigns'], 'reported statistics differ from raw samples')
    require(type(document['signals']) is int and document['signals'] == sum(row['signal'] for row in rows),
            'reported signal count differs')
    require(document['signals'] == 0, 'timing signal remains unresolved')
    flags = '-C target-cpu=generic'
    if route in timing.COMPILED:
        flags += ' -C target-feature=' + ({'sha1': '+sha,+sse2', 'md5': '+avx2'} if arch == 'x86_64'
                                         else {'sha1': '+neon,+sha2', 'md5': '+neon'})[family]
        probe = document['generic_host_probe']
        require(isinstance(probe, dict) and set(probe) == {'compile_command', 'command', 'output'}
                and probe['output'] == 'LEGACY_HMAC_HOST_FEATURES: ' + family + '\n', 'CPU probe missing/changed')
        compile_probe = probe['compile_command']
        require(isinstance(compile_probe, list) and len(compile_probe) == 8
                and compile_probe[:5] == ['rustc', '+1.99.1', '--edition=2024', '-C', 'target-cpu=generic']
                and isinstance(compile_probe[5], str)
                and compile_probe[5].endswith('/assurance/legacy-hmac-timing/host_probe.rs')
                and compile_probe[6] == '-o' and isinstance(compile_probe[7], str)
                and compile_probe[7].endswith('/generic-host-probe')
                and probe['command'] == [compile_probe[7], family], 'generic CPU probe command changed')
    else:
        require(document['generic_host_probe'] is None, 'unexpected compiled probe')
    require(document['build_rustflags'] == flags, 'build feature selection changed')
    build, command = document['build_command'], document['command']
    require(isinstance(build, list) and len(build) == 8 and build[:7] == [
        'cargo', '+1.99.1', 'build', '--release', '--locked', '--offline', '--manifest-path']
        and isinstance(build[-1], str) and build[-1].endswith('/assurance/legacy-hmac-timing/Cargo.toml'),
        'build command changed')
    require(isinstance(command, list) and len(command) == 3 and command[1:] == [route, family]
            and isinstance(command[0], str) and command[0].endswith('/release/brynja-legacy-hmac-timing'),
            'measured command changed')
    hashes = document['sources_sha256']
    require(isinstance(hashes, dict) and set(hashes) == set(current) == set(anchor), 'source inventory changed')
    require(MANIFESTS <= hashes.keys() and bool(hashes), 'source manifests absent')
    for name, digest in hashes.items():
        require(isinstance(name, str) and str(PurePosixPath(name)) == name
                and not name.startswith('/') and '..' not in PurePosixPath(name).parts, 'unsafe source path')
        require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'source digest syntax')
        require(sha(anchor[name]) == digest, 'explicit source anchor does not match capture: ' + name)
    changes = sorted(name for name in current if sha(current[name]) != hashes[name])
    if changes:
        require(set(changes) == MANIFESTS, 'measured source changed: ' + repr(changes))
        workspace_move(anchor, current)
    return {'route': route, 'family': family, 'target': target, 'capture_head': document['head'],
            'capture_head_mismatches': sorted(name for name, digest in hashes.items()
                                              if captured_head.get(name) is None or sha(captured_head[name]) != digest),
            'source_count': len(hashes), 'current_manifest_changes': changes,
            'campaign_count': len(rows), 'signals': 0, 'output_sha256': document['output_sha256'],
            'status': 'source/statistics reconciled; NOT release approval'}
