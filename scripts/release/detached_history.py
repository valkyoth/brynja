"""Read immutable schema-2/3 evidence on a different collecting machine.

Recorded source/tool seals describe execution, not tools installed today. The
live collector and resume runner still probe their tools. This offline reader
never executes archived code and grants no release authority. Like the runner,
its digests detect owner-side drift, not forgery by a malicious evidence owner.
"""
from __future__ import annotations

import math
import re
from pathlib import Path

import detached_checkpoints as checkpoints
import detached_job as jobs
import detached_manifest as records
import detached_shards as shards


def receipt_ok(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def tool_record(manifest: dict, root: Path) -> None:
    """Require the original complete inventory, without probing this host."""
    tools = manifest['tools']
    base = {'python', 'platform', 'rustc', 'cargo', 'rustup', 'installed', 'python3'}
    if (not isinstance(tools, dict) or not base <= tools.keys()
            or any(not isinstance(v, str) or not v.strip() or len(v) > 65536
                   for v in tools.values())):
        raise ValueError('incomplete historical tool identity')
    compilers = {'compiler:' + line.split()[0] for line in tools['installed'].splitlines()
                 if line.strip()}
    if not compilers or set(tools) != base | compilers | set(records.verifier_commands(root, manifest['commands'])):
        raise ValueError('historical compiler/verifier identity missing or unexpected')


class History:
    def __init__(self, locations: dict[str, Path]):
        self.locations = locations
        self.cache = {}
        self.active = set()
        self.visits = 0

    def completed(self, receipt: str, depth: int = 0, *, allow_failed=False) -> tuple[dict, dict, dict]:
        if depth > 16 or receipt in self.active:
            raise ValueError('historical checkpoint ancestry exceeds bound or cycles')
        if receipt in self.cache:
            if self.cache[receipt][1]['state'] == 'failed' and not allow_failed:
                raise ValueError('failed history requires explicit recovery')
            return self.cache[receipt]
        self.visits += 1
        if self.visits > 128 or not receipt_ok(receipt) or receipt not in self.locations:
            raise ValueError('missing or excessive historical receipt locations')
        self.active.add(receipt)
        job = records.safe_path(self.locations[receipt])
        manifest = jobs.load(job, receipt)
        if manifest['schema'] not in (2, 3):
            raise ValueError('historical reuse requires schema-2/3 post-execution seals')
        state, terminal = records.read(job / 'state.json'), records.read(job / 'result.json')
        if (set(state) != {'state', 'manifest', 'result_sha256'}
                or set(terminal) != {'schema', 'manifest', 'state', 'started', 'ended',
                                     'elapsed_seconds', 'results', 'failure_class', 'resources'}
                or state['manifest'] != receipt or state['result_sha256'] != records.digest(terminal)
                or terminal['manifest'] != receipt or type(terminal['schema']) is not int
                or terminal['schema'] != manifest['schema'] or terminal['state'] != state['state']
                or state['state'] not in ({'passed', 'partial', 'cancelled', 'timed_out', 'log_limit'}
                                         | ({'failed'} if allow_failed else set()))
                or terminal['failure_class'] is not None):
            raise ValueError('historical terminal result is unsuccessful or corrupted')
        jobs.validate_usage(terminal['resources'])
        elapsed = terminal['elapsed_seconds']
        if (type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0
                or not isinstance(terminal['results'], list)
                or len(terminal['results']) > len(manifest['commands'])):
            raise ValueError('invalid historical result observations')
        # Recompute frozen sources and command coverage with trusted current
        # tooling. Never import or execute a validator from the archived tree.
        for root in {job / 'source', *(shards.source(job, i, manifest['shards'])
                                      for i in range(manifest['shards']))}:
            jobs.validate_source(manifest, root, historical=True)
            if records.git(root, 'status', '--porcelain', '--untracked-files=all').strip():
                raise ValueError('historical source is not a clean committed snapshot')
        tool_record(manifest, job / 'source')
        import detached_recovery as recovery
        recovered = recovery.expected(manifest, job / 'source', self)
        found, seen, total = {}, set(), 0
        for record in terminal['results']:
            index = record.get('index')
            if type(index) is not int or index in seen or not 0 <= index < len(manifest['commands']):
                raise ValueError('duplicate or invalid historical command')
            seen.add(index)
            if (record.get('command') != manifest['commands'][index]
                    or record != records.read(job / f'command-{index:04d}.json')):
                raise ValueError('historical command record changed')
            if record['state'] in {'passed', 'reused'}:
                checkpoints.validate_record(manifest, job, record, recovered=recovered)
                found[index] = record
                total += record['log_bytes']
            else:
                # Failed/cancelled logs are retained and checked, never credited.
                allowed = {'cancelled', 'timed_out', 'log_limit'} | ({'failed'} if allow_failed else set())
                expected_keys = {'state', 'exit_code', 'elapsed_seconds', 'log_bytes', 'index', 'command',
                                 'started', 'ended', 'log', 'log_sha256', 'checks'}
                if (set(record) != expected_keys or record['state'] not in allowed
                        or record['log'] != f'command-{index:04d}.log'
                        or record['checks'] is not None
                        or type(record['log_bytes']) is not int or record['log_bytes'] < 0
                        or type(record['elapsed_seconds']) not in (int, float)
                        or not math.isfinite(record['elapsed_seconds']) or record['elapsed_seconds'] < 0
                        or (record['state'] == 'failed' and
                            (type(record['exit_code']) is not int or record['exit_code'] == 0))
                        or record['log_sha256'] != records.file_hash(job / record['log'], manifest['log_bytes'])
                        or record['log_bytes'] != (job / record['log']).stat().st_size):
                    raise ValueError('invalid failed/interrupted historical command')
        if terminal['state'] == 'failed' and not any(r['state'] == 'failed' for r in terminal['results']):
            raise ValueError('failed history lacks an investigated command failure')
        inherited = self.parents(manifest, depth + 1)
        if any(found.get(index) != record for index, record in inherited.items()):
            raise ValueError('historical inherited checkpoint missing or replaced')
        if terminal['state'] in {'passed', 'partial'}:
            expected = (set(range(len(manifest['commands']))) if terminal['state'] == 'passed'
                        else checkpoints.indices(manifest) | set(inherited) | set(recovered))
            if (set(found) != expected or len(found) != len(terminal['results'])
                    or list(found) != sorted(found)
                    or (job / 'cancel').exists() or elapsed > manifest['seconds'] + 10
                    or total > manifest['log_bytes']):
                raise ValueError('historical completion coverage or resource budget mismatch')
        self.active.remove(receipt)
        self.cache[receipt] = manifest, terminal, found
        return self.cache[receipt]

    def parents(self, manifest: dict, depth: int) -> dict:
        refs = manifest['resume']
        if refs is None:
            return {}
        refs = [refs] if isinstance(refs, dict) else refs
        if not isinstance(refs, list) or not 1 <= len(refs) <= 8:
            raise ValueError('invalid historical parent count')
        found, seen = {}, set()
        for ref in refs:
            if (not isinstance(ref, dict) or set(ref) != {'job', 'receipt'}
                    or not isinstance(ref['job'], str) or not Path(ref['job']).is_absolute()
                    or not receipt_ok(ref['receipt']) or ref['receipt'] in seen):
                raise ValueError('invalid or duplicate historical parent')
            seen.add(ref['receipt'])
            parent, _, passed = self.completed(ref['receipt'], depth)
            for field in ('sources', 'tools', 'commands', 'plan', 'phases', 'approval', 'miri_profile'):
                if parent[field] != manifest[field]:
                    raise ValueError('historical parent execution inputs differ: ' + field)
            if parent.get('recovery') != manifest.get('recovery'):
                raise ValueError('historical recovery ancestry changed')
            for index, record in passed.items():
                found.setdefault(index, record)
        return found

    def collect(self, receipt: str) -> dict:
        manifest, terminal, found = self.completed(receipt)
        if terminal['state'] != 'passed':
            raise ValueError('phase evidence requires a fully completed historical job')
        return {'state': 'validated', 'manifest': receipt, 'commands': len(found),
                'phases': manifest['phases'], 'tool_identity': 'original execution seals',
                'release_authorized': False}
