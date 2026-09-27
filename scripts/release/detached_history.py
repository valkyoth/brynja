"""Read immutable schema-2 evidence on a different collecting machine.

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

    def completed(self, receipt: str, depth: int = 0) -> tuple[dict, dict, dict]:
        if depth > 16 or receipt in self.active:
            raise ValueError('historical checkpoint ancestry exceeds bound or cycles')
        if receipt in self.cache:
            return self.cache[receipt]
        self.visits += 1
        if self.visits > 128 or not receipt_ok(receipt) or receipt not in self.locations:
            raise ValueError('missing or excessive historical receipt locations')
        self.active.add(receipt)
        job = records.safe_path(self.locations[receipt])
        manifest = jobs.load(job, receipt)
        if manifest['schema'] != 2:
            raise ValueError('historical reuse requires schema-2 post-execution seals')
        state, terminal = records.read(job / 'state.json'), records.read(job / 'result.json')
        if (set(state) != {'state', 'manifest', 'result_sha256'}
                or set(terminal) != {'schema', 'manifest', 'state', 'started', 'ended',
                                     'elapsed_seconds', 'results', 'failure_class', 'resources'}
                or state['manifest'] != receipt or state['result_sha256'] != records.digest(terminal)
                or terminal['manifest'] != receipt or type(terminal['schema']) is not int
                or terminal['schema'] != 2 or terminal['state'] != state['state']
                or state['state'] not in {'passed', 'partial', 'cancelled', 'timed_out', 'log_limit'}
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
            jobs.validate_source(manifest, root)
            if records.git(root, 'status', '--porcelain', '--untracked-files=all').strip():
                raise ValueError('historical source is not a clean committed snapshot')
        tool_record(manifest, job / 'source')
        found, seen, total = {}, set(), 0
        for record in terminal['results']:
            index = record.get('index')
            if type(index) is not int or index in seen or not 0 <= index < len(manifest['commands']):
                raise ValueError('duplicate or invalid historical command')
            seen.add(index)
            if (record.get('command') != manifest['commands'][index]
                    or record != records.read(job / f'command-{index:04d}.json')):
                raise ValueError('historical command record changed')
            if record['state'] == 'passed':
                checkpoints.validate_record(manifest, job, record)
                found[index] = record
                total += record['log_bytes']
            elif record['state'] not in {'cancelled', 'timed_out', 'log_limit'}:
                raise ValueError('failed historical command requires investigation')
        inherited = self.parents(manifest, depth + 1)
        if any(found.get(index) != record for index, record in inherited.items()):
            raise ValueError('historical inherited checkpoint missing or replaced')
        if terminal['state'] in {'passed', 'partial'}:
            expected = (set(range(len(manifest['commands']))) if terminal['state'] == 'passed'
                        else checkpoints.indices(manifest) | set(inherited))
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
