"""Run exactly one operator-selected catalog command, bounded and logged."""
from __future__ import annotations

import os
import signal
import uuid

import detached_manifest as records
import detached_process
import verification_plan as plans
from test_dashboard_store import prepare, stamp


def run(root, store, item, seconds=300, maximum=16 * 1024 * 1024):
    if not 1 <= seconds <= 86400 or not 1 <= maximum <= 1024 ** 3:
        raise ValueError('invalid time/log budget')
    plan = plans.build(root=root)
    issues = plans.environment_issues(dict(os.environ),
        plans.inputs.document((root / 'rust-toolchain.toml').read_bytes())['toolchain']['channel'])
    if issues:
        raise ValueError('; '.join(issues))
    store = prepare(store)
    # One global local runner lock: no accidental simultaneous builds sharing
    # target dirs. A crashed lock is not removed automatically by another run.
    lock = store / 'runner.lock'
    with lock.open('x') as stream:
        stream.write(str(os.getpid()) + '\n')
    previous = {}
    try:
        folder = store / uuid.uuid4().hex
        folder.mkdir(mode=0o700)
        cancel = folder / 'cancel'
        log = folder / 'output.log'
        path = store / (folder.name + '.json')
        source = records.digest(records.sources(root))
        tools = records.tool_identity(root, [item['entry']])
        row = {'id': item['id'], 'families': item['families'],
               'phase': item['entry']['phase'], 'label': item['label'],
               'state': 'running', 'ended': stamp(), 'started': stamp(), 'seconds': 0,
               'origin': 'local diagnostic (not gate evidence)', 'commit': plan['head'],
               'source_identity': source, 'log': str(log), 'pid': os.getpid(),
               'command': item['entry'], 'tools': tools}
        document = {'schema': 1, 'release_authorized': False, 'observations': [row]}
        records.atomic(path, document)

        def stop(_signum, _frame):
            cancel.touch(exist_ok=True)

        for name in (signal.SIGINT, signal.SIGTERM):
            previous[name] = signal.signal(name, stop)
        print(f'Running ONE task, limit {seconds}s. Log: {log}', flush=True)
        try:
            result = detached_process.execute(item['entry']['argv'], root, log, cancel,
                seconds=seconds, maximum=maximum,
                environment={**os.environ, **item['entry']['environment']},
                stdin=item['entry']['stdin'])
            row.update(state=result['state'], seconds=result['elapsed_seconds'],
                       exit_code=result['exit_code'])
            if row['state'] == 'passed' and (source != records.digest(records.sources(root))
                    or tools != records.tool_identity(root, [item['entry']])):
                row['state'] = 'invalidated'
        except Exception:
            row['state'] = 'failed'
            raise
        finally:
            row['ended'] = stamp()
            if log.exists():
                row['log_sha256'] = records.file_hash(log, maximum)
            records.atomic(path, document)
        return row
    finally:
        for name, handler in previous.items():
            signal.signal(name, handler)
        lock.unlink()
