#!/usr/bin/env python3
"""Terminal test dashboard: browse, inspect, import and run ONE check."""
import argparse
import json
import os
from pathlib import Path
import shlex
import sys

import detached_catalog
import verification_plan as plans
from test_dashboard_catalog import inventory, matrix_mode
import test_dashboard_store as store
import test_dashboard_run as runner


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--store', type=Path,
                        default=plans.ROOT.parent / 'brynja-evidence/dashboard')
    parser.add_argument('--phase', choices=detached_catalog.PHASES, action='append')
    parser.add_argument('--family', help='implementation name, e.g. kmac, sha2, legacy_hmac')
    parser.add_argument('--profile', choices=('routine', 'extended', 'existing-full'), default='extended')
    sub = parser.add_subparsers(dest='action')
    listing = sub.add_parser('list', help='summary by implementation; default command')
    listing.add_argument('--tasks', action='store_true', help='show individual runnable work items')
    listing.add_argument('--offset', type=int, default=0)
    listing.add_argument('--limit', type=int, default=50, help='maximum task rows per page')
    sub.add_parser('show', help='exact command and latest provenance').add_argument('id')
    run = sub.add_parser('run', help='run exactly one task; never launch a whole family implicitly')
    run.add_argument('id')
    run.add_argument('--seconds', type=int, default=300)
    run.add_argument('--yes', action='store_true', help='confirm this one task noninteractively')
    importing = sub.add_parser('import-job', help='validate saved detached receipt before indexing')
    importing.add_argument('job', type=Path)
    importing.add_argument('--receipt', required=True)
    importing.add_argument('--locations', type=Path,
        help='local receipt-locations.json for relocated parent jobs (never an approval)')
    sub.add_parser('history', help='all recorded observations, including retired task IDs')
    sub.add_parser('slow', help='20 slowest saved observations; no tests started')
    args = parser.parse_args()
    if args.action == 'import-job':
        print(json.dumps(store.import_job(args.store, args.job.absolute(), args.receipt,
                                         locations=args.locations), indent=2))
        return 0
    observations = store.read(args.store)
    if args.action == 'history':
        print(json.dumps(observations, indent=2))
        return 0
    if args.action == 'slow':
        labels = {i['id']: i['label'] for i in inventory(
            plans.ROOT, args.phase or list(detached_catalog.PHASES), args.profile)}
        rows = [r for r in store.latest(observations).values()
                if (not args.family or args.family in r['families'])
                and (not args.phase or r['phase'] in args.phase) and 'seconds' in r]
        for row in sorted(rows, key=lambda r: r.get('seconds', 0), reverse=True)[:20]:
            print(f'{row["id"]:28} {store.duration(row.get("seconds", 0)):9} '
                  f'{store.text(row["state"]):12} {store.brief(labels.get(row["id"], row["label"]), 52)}')
        return 0
    items = inventory(plans.ROOT, args.phase or list(detached_catalog.PHASES), args.profile)
    if args.family:
        if not any(args.family in item['families'] for item in items):
            raise ValueError('unknown family or no tasks in selected phases')
        items = [i for i in items if args.family in i['families']]
    if args.action in (None, 'list'):
        print(f'Brynja test dashboard — Miri profile: {args.profile}; '
              f'compiler matrix: {matrix_mode(plans.ROOT)}; no tests started\n')
        if getattr(args, 'tasks', False):
            if args.offset < 0 or not 1 <= args.limit <= 1000:
                raise ValueError('offset must be nonnegative; limit must be 1..1000')
            total = len(items)
            items = items[args.offset:args.offset + args.limit]
            print(f'Task page: offset {args.offset}, {len(items)} of {total} rows; use --offset/--limit to page.')
        store.render(items, observations, tasks=getattr(args, 'tasks', False), family=args.family)
        return 0
    matching = [i for i in items if i['id'] == args.id]
    if len(matching) != 1:
        raise ValueError('unknown task ID for selected phase/profile; list current IDs first')
    item = matching[0]
    if args.action == 'show':
        print(json.dumps({'task': item, 'latest': store.latest(observations).get(item['id']),
                          'current_applicability': 'not assessed', 'release_authorized': False}, indent=2))
        return 0
    print(store.text(shlex.join(item['entry']['argv'])))
    if item['bundled']:
        print('Warning: this catalog command is a suite, not a single Rust test; it may be slow.')
    if not args.yes and input(f'Run this ONE task with a {args.seconds}s limit? [y/N] ').strip().lower() != 'y':
        print('Nothing started.')
        return 0
    row = runner.run(plans.ROOT, args.store, item, args.seconds)
    print(f'{row["state"]}: {store.duration(row["seconds"])}; log: {row["log"]}')
    return 0 if row['state'] == 'passed' else 1


if __name__ == '__main__':
    try:
        exit_code = main()
        sys.stdout.flush()
        raise SystemExit(exit_code)
    except BrokenPipeError:
        # Piping a long list to head is a normal read-only operation.
        with open(os.devnull, 'w') as sink:
            os.dup2(sink.fileno(), sys.stdout.fileno())
        raise SystemExit(0)
    except (ValueError, OSError, RuntimeError, EOFError) as error:
        print('Dashboard: ' + store.text(error))
        raise SystemExit(1)
