"""Explicit recovery of sealed passes; failed jobs and original seals stay intact.

Reuse is conservative at the implementation-family boundary. Current baseline
checks always run. Recovery records cite original receipts, never manufacture a
new execution seal for an old log. Unknown/changed inputs execute again.
"""
from pathlib import Path
import shutil

import detached_manifest as records
import verification_carry_forward as carry
import verification_plan as plans
import verification_units as units
import miri_coverage_identity as miri_identity


def references(manifest):
    refs = manifest.get('recovery')
    if refs is None:
        return []
    if manifest.get('schema') != 3 or not isinstance(refs, list) or not 1 <= len(refs) <= 8:
        raise ValueError('invalid recovery references')
    found = set()
    for ref in refs:
        if (not isinstance(ref, dict) or set(ref) != {'job', 'receipt'}
                or not isinstance(ref['job'], str) or not Path(ref['job']).is_absolute()
                or not isinstance(ref['receipt'], str) or len(ref['receipt']) != 64
                or any(c not in '0123456789abcdef' for c in ref['receipt'])
                or ref['receipt'] in found):
            raise ValueError('invalid/duplicate recovery reference')
        records.safe_path(Path(ref['job']))
        found.add(ref['receipt'])
    return refs


def expected(manifest, root, reader=None):
    refs = references(manifest)
    if not refs:
        return {}
    import detached_history as history
    historical = reader is not None
    if reader is None:
        reader = history.History(locations(refs))
    found = {}
    for ref in refs:
        if ref['receipt'] not in reader.locations:
            raise ValueError('missing recovery ancestor location')
        old, terminal, passed = reader.completed(ref['receipt'], allow_failed=True)
        # Even explicit recovery cannot reuse a changed compiler/interpreter.
        if old['tools'] != manifest['tools']:
            continue
        source = old['sources']['head']
        records.git(root, 'merge-base', '--is-ancestor', source, 'HEAD')
        delta = plans.build(root=root, base=source, verified_base=True)
        delta['evidence'] = {'changed_paths': plans.changed_paths(root, source)}
        context = {'plan': delta, 'manifest': {**old, 'commands': [r['command'] for r in passed.values()]},
                   'test_only_rerun': carry.test_only.prove(root, source, delta['evidence']['changed_paths']),
                   'miri_decomposition_groups': carry.decomposition.prove(
                       root, source, delta['evidence']['changed_paths']),
                   'public_checkpoint': plans.new_full_checkpoint(manifest['plan'], old['plan'])}
        # Only a History reader reconstructs an already sealed recovery. New
        # jobs and current carry-forward decisions retain today's ownership.
        if historical:
            context['historical_ownership_root'] = root
        old_root = reader.locations[ref['receipt']] / 'source'
        meaning = miri_identity.Coverage(old_root, root)
        context.update(coverage_roots=(old_root, root), miri_coverage=meaning)
        # Build once: thousands of split tasks must not scan/reparse every old
        # task for each candidate. The index contains validated passes only.
        miri_passes, other_passes = {}, []
        for i, record in passed.items():
            if miri_identity.is_task(record['command']):
                miri_passes.setdefault(meaning.old.key(record['command']), []).append((i, record))
            else:
                other_passes.append((i, record))
        for index, entry in enumerate(manifest['commands']):
            if index in found:
                continue
            matches = (miri_passes.get(meaning.new.key(entry), []) if miri_identity.is_task(entry)
                       else [(i, r) for i, r in other_passes
                             if units.covers(r['command'], entry, old_root, root)])
            if not matches:
                continue
            # Coverage has already been established above, including whole-suite
            # to unit-group expansion. The existing source-delta policy must
            # still permit reuse of this particular implementation check.
            previous_index, previous = matches[0]
            scoped = {**context, 'manifest': {**old, 'commands': [previous['command']]}}
            if not carry.disposition(entry, scoped).startswith('reuse:'):
                continue
            found[index] = {
                'state': 'reused', 'index': index, 'command': entry,
                'origin': {'receipt': ref['receipt'], 'index': previous_index},
                'log': f'command-{index:04d}.log', 'log_bytes': previous['log_bytes'],
                'log_sha256': previous['log_sha256'],
            }
    return found


def locations(refs):
    """Resolve local ancestry once, with receipt checks and finite traversal."""
    import detached_job as jobs
    found, pending = {}, list(refs)
    while pending:
        ref = pending.pop()
        if len(found) >= 128:
            raise ValueError('excessive recovery ancestry')
        path = records.safe_path(Path(ref['job']))
        if ref['receipt'] in found:
            if found[ref['receipt']] != path:
                raise ValueError('conflicting recovery location')
            continue
        parent = jobs.load(path, ref['receipt'])
        found[ref['receipt']] = path
        pending.extend(references(parent))
        resume = parent.get('resume') or []
        pending.extend([resume] if isinstance(resume, dict) else resume)
    return found


def validate_record(manifest, job, record, recovered):
    index = record.get('index')
    if (recovered is None or type(index) is not int or recovered.get(index) != record
            or record != records.read(job / f'command-{index:04d}.json')
            or record['log_sha256'] != records.file_hash(job / record['log'], manifest['log_bytes'])
            or record['log_bytes'] != (job / record['log']).stat().st_size):
        raise ValueError('recovered command provenance/log mismatch')


def install(manifest, job):
    found = expected(manifest, job / 'source')
    refs = {ref['receipt']: Path(ref['job']) for ref in references(manifest)}
    for index, record in found.items():
        origin = record['origin']
        path = records.safe_path(refs[origin['receipt']] / f'command-{origin["index"]:04d}.log')
        with (job / record['log']).open('xb') as output, path.open('rb') as source:
            shutil.copyfileobj(source, output)
        records.atomic(job / f'command-{index:04d}.json', record)
        validate_record(manifest, job, record, found)
    return found
