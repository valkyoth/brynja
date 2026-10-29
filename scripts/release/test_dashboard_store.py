"""Local diagnostic history; never an approval manifest or gate receipt."""
from __future__ import annotations

import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

import detached_manifest as records
from detached_history import History
from test_dashboard_catalog import describe
import test_dashboard_provenance as provenance

STATES = {'passed', 'reused', 'failed', 'cancelled', 'timed_out', 'log_limit',
          'running', 'interrupted', 'invalidated'}


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def prepare(path):
    path = records.safe_path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ValueError('dashboard history directory must be owned by you with mode 0700')
    return path


def save(store, data):
    records.atomic(store / (uuid.uuid4().hex + '.json'), data)


def read(store):
    if not store.exists():
        return []
    prepare(store)
    observations = []
    paths = sorted(store.glob('*.json'))
    if len(paths) > 10000:
        raise ValueError('dashboard history file limit exceeded')
    for path in paths:
        document = records.read(path)
        if document.get('schema') != 1 or document.get('release_authorized') is not False:
            raise ValueError('invalid dashboard history header: ' + path.name)
        rows = document.get('observations')
        if not isinstance(rows, list) or len(rows) > records.MAX_COMMANDS:
            raise ValueError('invalid dashboard history population')
        for row in rows:
            if (not isinstance(row, dict) or row.get('state') not in STATES
                    or not isinstance(row.get('id'), str)
                    or not isinstance(row.get('ended'), str)):
                raise ValueError('invalid dashboard observation')
            observations.append(row)
    return observations


def latest(rows):
    result = {}
    for row in rows:
        previous = result.get(row['id'])
        if previous is None or row['ended'] > previous['ended']:
            result[row['id']] = row
    return result


def import_job(store, job, receipt, *, locations=None):
    # Only the trusted current historical reader executes. Archive scripts are
    # not imported. Cancelled tasks remain cancelled, never counted as passes.
    lookup = {}
    if locations is not None:
        index = records.read(locations)
        if (set(index) != {'schema', 'jobs'} or type(index['schema']) is not int or index['schema'] != 1
                or not isinstance(index['jobs'], dict) or len(index['jobs']) > 4096):
            raise ValueError('invalid relocated receipt index')
        for identity, path in index['jobs'].items():
            if (not isinstance(identity, str) or len(identity) != 64
                    or any(c not in '0123456789abcdef' for c in identity)
                    or not isinstance(path, str) or not Path(path).is_absolute()):
                raise ValueError('invalid relocated receipt location')
            lookup[identity] = records.safe_path(Path(path))
    lookup[receipt] = records.safe_path(job)
    reader = History(lookup)
    manifest, terminal, passed = reader.completed(receipt)
    rows, cache = [], {}
    for record in terminal['results']:
        item = describe(record['command'], job / 'source', cache)
        reused = record['state'] == 'reused'
        if reused and record['index'] not in passed:
            raise ValueError('dashboard reuse record was not validated')
        timing = (provenance.execution(reader, record) if reused else
                  {'ended': record['ended'], 'seconds': record['elapsed_seconds']})
        rows.append({'id': item['id'], 'families': item['families'],
                     'phase': record['command']['phase'], 'label': item['label'],
                     'state': 'reused' if reused else 'passed' if record['index'] in passed else record['state'],
                     **timing,
                     'origin': 'validated historical receipt', 'receipt': receipt,
                     'commit': manifest['plan']['head'],
                     'log': str(job / record['log']),
                     'log_sha256': record['log_sha256'],
                     'source_identity': records.digest(manifest['sources']),
                     'campaign_state': terminal['state']})
    save(prepare(store), {'schema': 1, 'release_authorized': False,
                          'observations': rows})
    return {'receipt': receipt, 'campaign_state': terminal['state'],
            'passes': sum(r['state'] == 'passed' for r in rows),
            'reused': sum(r['state'] == 'reused' for r in rows),
            'covered': len(passed), 'recorded': len(rows), 'release_authorized': False}


def text(value):
    # Never emit terminal controls from imported labels/paths/host observations.
    return ''.join(c if c.isprintable() else '?' for c in str(value))


def duration(seconds):
    seconds = int(seconds)
    return f'{seconds // 3600}h{seconds % 3600 // 60:02}m' if seconds >= 3600 else f'{seconds // 60}m{seconds % 60:02}s'


def brief(value, reserved=75):
    width = max(35, shutil.get_terminal_size(fallback=(160, 24)).columns - reserved)
    clean = text(value)
    return clean if len(clean) <= width else clean[:width - 3] + '...'


def render(items, observations, *, tasks=False, family=None):
    known = latest(observations)
    if tasks:
        print(f'{"ID":28} {"RESULT":12} {"LAST RUN (UTC)":21} {"DURATION":9} TEST')
        for item in items:
            row = known.get(item['id'], {})
            print(f'{item["id"]:28} {text(row.get("state", "never run")):12} '
                  f'{text(row.get("ended", "-")).replace("+00:00", "Z")[:20]:21} '
                  f'{duration(row["seconds"]) if "seconds" in row else "-":9} '
                  f'{brief(item["label"])}')
        return
    groups = {}
    for item in items:
        for owner in item['families']:
            if family is None or owner == family:
                groups.setdefault((owner, item['entry']['phase']), []).append(item)
    print(f'{"IMPLEMENTATION":16} {"CHECK":11} {"COVERED/TOTAL":13} {"REUSED":7} {"STATUS":15} {"LAST RUN (UTC)":21} LONGEST')
    for (family, phase), subset in sorted(groups.items()):
        rows = [known[i['id']] for i in subset if i['id'] in known]
        passed = sum(r['state'] == 'passed' for r in rows)
        reused = sum(r['state'] == 'reused' for r in rows)
        failed = any(r['state'] in {'failed', 'invalidated'} for r in rows)
        status = ('failures' if failed else 'all observed' if passed + reused == len(subset)
                  else 'partial' if rows else 'never run')
        date = max((r['ended'] for r in rows), default='-')
        longest = max((r.get('seconds', 0) for r in rows), default=0)
        print(f'{family:16} {phase:11} {str(passed + reused)+"/"+str(len(subset)):13} {reused:<7} '
              f'{status:15} {text(date).replace("+00:00", "Z")[:20]:21} {duration(longest)}')
    print('\nHistorical/diagnostic observations only; current source/tool applicability is NOT assessed.')
    print('Partial is not PASS. No dashboard result authorizes a release; use show ID for provenance.')
