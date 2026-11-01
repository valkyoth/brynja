"""Explicit, non-executing inventory export using the existing catalog readers.

Discovery is not scope approval. Imported observations remain historical, not
current passes. No verifier, archived Python, tool installation or remote runs.
"""
import collections
import datetime
import hashlib
import json
import re
import tomllib
from pathlib import Path

import detached_catalog
import test_dashboard_catalog as dashboard
import verification_plan as plans
import verification_manual_diagnostics as manual

ROOT = Path(__file__).resolve().parents[2]
UNRESOLVED = ('Scoped input/configuration and completion bindings have not been migrated to the Rust runner. '
              'Historical results do not establish a current pass; inspect the existing command and its prerequisites. '
              'No automatic run or release obligation.')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def definitions(root=ROOT):
    groups = list(plans.scope.GROUPS)
    plan = dict(stage='internal', verification_mode='full', approval_required=False,
                fingerprint='', groups=groups,
                verifiers={p: groups for p in ('miri', 'kani', 'asan')},
                full_phases=list(detached_catalog.PHASES))
    result = {}
    for profile in ('extended', 'routine', 'existing-full'):
        phases = list(detached_catalog.PHASES) if profile == 'extended' else ['miri']
        entries = detached_catalog.selected(plan, phases, None, shards=4, root=root,
                    miri_tasks=True, miri_profile=profile, unit_tests=True)
        cache = {}
        for entry in entries:
            item = dashboard.describe(entry, root, cache)
            row = dict(id=item['id'], families=item['families'], phase=entry['phase'],
                       label=item['label'], command=entry['argv'], environment=entry['environment'],
                       stdin=entry['stdin'], definition=item['definition'],
                       reason=UNRESOLVED, history=[])
            # The old blanket repository group obscured these component
            # contracts. Preserve IDs/commands/history; give them their actual
            # owning component instead of making every repository task a peer.
            if entry['phase'] == 'repository' and len(entry['argv']) == 2 and entry['argv'][0] == 'python3':
                path = entry['argv'][1]
                if path in {f'scripts/pki/{mode}-{name}.py' for mode in ('check', 'test')
                            for name in ('der-reader', 'asn1-values')}:
                    row['families'] = ['pki']
                elif path in {f'scripts/protocols/{mode}-record-framing.py' for mode in ('check', 'test')}:
                    row['families'] = ['protocol']
            if item['id'] in result and result[item['id']] != row:
                raise ValueError('catalog identity collision')
            result[item['id']] = row
    # These old group selectors validate only inventory/tool availability. The
    # shell driver has no proof branch for them. Preserve IDs/history, but never
    # present them as missing proofs or successful proof executions.
    for row in result.values():
        if row['phase'] == 'kani' and row['families'] in [[x] for x in ('core', 'sanitization', 'legacy', 'acceleration', 'static_cpu')]:
            row['phase'] = 'inventory-only'
            row['reason'] = 'Historical Kani inventory/setup selector; executes no proof harness. Reference only, not a proof pass or missing proof requirement.'
    # List standalone checks/captures not already represented by a catalog
    # command. Their CLI arguments/platform setup must be supplied deliberately.
    referenced = {arg for row in result.values() for arg in row['command'] if arg.startswith('scripts/')}
    for path in sorted((root / 'scripts').glob('*/*')):
        if path.suffix not in ('.py', '.sh') or not re.match(r'^(?:check|test|capture|run)[-_]', path.name):
            continue
        relative = path.relative_to(root).as_posix()
        if relative in referenced:
            continue
        argv = ['python3', relative] if path.suffix == '.py' else ['bash', relative]
        # Broad orchestration directories are their own inventory components,
        # not a claim that every algorithm needs their tests. Do not import the
        # old planner's ALL-family fallback into everyday component selection.
        family = {'legacy-hash': 'legacy', 'legacy-hmac': 'legacy_hmac',
                  'cpu': 'acceleration', 'hash': 'hash-integration',
                  'cryptography': 'shared-cryptography', 'foundations': 'core'}.get(
                      path.parent.name, path.parent.name)
        families = [family]
        key = 'entry-' + digest(relative)[:16]
        result[key] = dict(id=key, families=families, phase='entrypoint', label=relative,
                           command=argv, environment={}, stdin=None,
                           definition={'path': relative}, history=[],
                           reason='Standalone entry point/helper: required arguments, platform and execution scope must be reviewed. ' + UNRESOLVED)
    # Explicit workflow entry points are visible even where their matrix/native
    # steps are not local standalone scripts. No GitHub API or workflow dispatch.
    for path in sorted((root / '.github/workflows').glob('*.yml')):
        name = path.relative_to(root).as_posix()
        for job in re.findall(r'^  ([a-zA-Z0-9_-]+):\s*$', path.read_text().split('\njobs:', 1)[-1], re.M):
            key = 'workflow-' + digest([name, job])[:16]
            result[key] = dict(id=key, families=['repository'], phase='workflow',
                               label=name + ' / ' + job, command=[], environment={}, stdin=None,
                               definition={'workflow': name, 'job': job}, history=[],
                               reason='GitHub workflow job; use the documented workflow/lane and platform setup. Never dispatched by this local tracker.')
    registry = tomllib.loads((root / 'verification/checks.toml').read_text())
    for include in registry.get('includes', []):
        path = Path(include)
        if path.is_absolute() or '..' in path.parts:
            raise ValueError('invalid registry fragment path')
        registry['checks'].extend(json.loads((root / path).read_text())['checks'])
    for check in registry['checks']:
        row = result.get(check['id'])
        category = check.get('category', 'portable')
        if row and check['component'] in row['families'] and (category == row['phase'] or (row['phase'] == 'miri' and category == 'miri-' + row['definition']['profile'])):
            row['reason'] = ('Runnable scoped binding: ' + check['component'] + '/' + check['id']
                             + ' in verification/checks.toml. This catalog retains original history, '
                               'not a current pass. Use show to inspect the binding and attempts.')
    bound = {c['id'] for c in registry['checks']}
    for row in result.values():
        explanation = manual.reason(row)
        if explanation:
            if row['id'] in bound:
                raise ValueError('manual diagnostic also registered for implicit execution: ' + row['id'])
            row['manual_diagnostic'] = True
            row['reason'] = explanation + ' Original command/history retained; never run implicitly.'
    return sorted(result.values(), key=lambda r: (r['phase'], r['id']))


def time_key(value):
    parsed = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('historical timestamp lacks timezone')
    return parsed.timestamp()


def history(rows, index, evidence_root):
    by_id = {r['id']: r for r in rows}
    seen = set()
    total = 0
    for file in index['files']:
        path = Path(file['path'])
        if path.is_absolute() or '..' in path.parts:
            raise ValueError('invalid history path')
        raw = (evidence_root / path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != file['sha256']:
            raise ValueError('historical dashboard digest changed: ' + str(path))
        doc = json.loads(raw)
        if doc.get('schema') != 1 or doc.get('release_authorized') is not False:
            raise ValueError('invalid historical observation header')
        for number, observation in enumerate(doc['observations']):
            total += 1
            key = observation['id']
            time_key(observation['ended'])
            # A reuse campaign commit is NOT necessarily the execution commit.
            source = observation.get('execution_commit')
            if not source and observation['state'] != 'reused':
                source = observation.get('commit')
            record = dict(result=observation['state'], ended=observation['ended'],
                          source=source or 'unresolved original execution (see receipt chain)',
                          campaign_commit=observation.get('commit', ''),
                          receipt=observation.get('receipt', ''),
                          log_sha256=observation.get('log_sha256', ''),
                          reference=str(path) + '#' + str(number))
            identity = digest([key, {k: v for k, v in record.items() if k != 'reference'}])
            if identity in seen:
                continue
            seen.add(identity)
            if key not in by_id:
                row = dict(id=key, families=observation['families'], phase='retired-history',
                           label=observation['label'], command=[], environment={}, stdin=None,
                           definition={'historical_phase': observation['phase']}, history=[],
                           reason='Historical task identity not in the current catalog. Preserve the old observation; do not reassign it to a new ordinal or command.')
                rows.append(row)
                by_id[key] = row
            by_id[key]['history'].append(record)
    for row in rows:
        # At equal timestamps show an unresolved failure rather than hide it
        # behind another import's success. Original times remain untouched.
        row['history'].sort(key=lambda r: (time_key(r['ended']), r['result'] not in ('passed', 'reused'), r['reference']))
    return dict(original_rows=total, unique_observations=len(seen))


def markdown(document):
    def safe(value):
        return ' '.join(str(value).split()).replace('|', '\\|')
    out = ['# Verification catalog', '',
           'Generated inventory, not a release gate or current-pass claim. All profiles are visible; overlapping profiles are not additional executions.',
           'Use `brynja-verify list COMPONENT [PHASE]` and `brynja-verify show COMPONENT ID` for commands and historical provenance.',
           'Runnable scoped bindings are in verification/checks.toml; list/show distinguish them from unresolved assessments. Owner-approved manual diagnostics, supporting entry points, workflow jobs and retired identities are references, not unfinished work. Do not rerun checks just to populate this list.', '',
           '| Component | Category | Assessments | With historical observations |', '| --- | --- | --- | --- |']
    grouped = collections.defaultdict(list)
    for row in document['entries']:
        for family in row['families']:
            grouped[family, row['phase']].append(row)
    for (family, phase), rows in sorted(grouped.items()):
        out.append(f'| {family} | {phase} | {len(rows)} | {sum(bool(r["history"]) for r in rows)} |')
    out += ['', '## Every catalog assessment', '', '| ID | Components | Category | Assessment | Latest historical outcome | Original time |', '| --- | --- | --- | --- | --- | --- |']
    for row in sorted(document['entries'], key=lambda r: (r['phase'], r['id'])):
        latest = row['history'][-1] if row['history'] else {}
        category = row['phase'] + (' (manual diagnostic)' if row.get('manual_diagnostic') else '')
        out.append('| ' + ' | '.join(map(safe, [row['id'], ', '.join(row['families']), category, row['label'], latest.get('result', 'No mapped observation'), latest.get('ended', '—')])) + ' |')
    return '\n'.join(out) + '\n'
