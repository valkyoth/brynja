#!/usr/bin/env python3
"""Explicit inventory/history reconciliation. Never executes verification."""
import argparse
import fcntl
import json
from pathlib import Path
import subprocess
import tempfile
import verification_catalog_export as catalog


def write(path, data):
    if path.exists() and path.read_text() == data:
        return
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(data)
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='Explicitly reconcile catalog and saved history; no tests')
    args = parser.parse_args()
    rows = catalog.definitions()
    path = catalog.ROOT / 'verification/catalog.json'
    if not args.write:
        existing = json.loads(path.read_text())
        known = [{**r, 'history': []} for r in existing['entries'] if r['phase'] != 'retired-history']
        if known != rows:
            raise ValueError('catalog definitions changed; explicitly reconcile the inventory, not the tests')
        print(f'{len(rows)} catalog definitions reconciled; no verification executed')
        return
    index = json.loads((catalog.ROOT / 'verification/historical-index.json').read_text())
    counts = catalog.history(rows, index, (catalog.ROOT / index['local_evidence_root']).resolve())
    document = dict(schema=1, source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=catalog.ROOT, text=True).strip(),
                    scope='All three existing Miri profiles, full compiler catalog, ASan/Kani/repository tasks, standalone script entry points, workflow jobs and retired saved identities. Discovery only; no current evidence applicability inferred.',
                    history_counts=counts, entries=rows)
    lock = catalog.ROOT / 'verification/.runner/lock'
    lock.parent.mkdir(parents=True, exist_ok=True)
    with lock.open('a+') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        header = {k: v for k, v in document.items() if k != 'entries'}
        # One assessment per line keeps future inventory changes reviewable;
        # no multi-megabyte single-line diff or embedded execution logs.
        encoded = json.dumps(header, indent=2, ensure_ascii=False).rstrip()[:-1].rstrip()
        encoded += ',\n  "entries": [\n' + ',\n'.join(
            '    ' + json.dumps(row, separators=(',', ':'), ensure_ascii=False) for row in rows)
        write(path, encoded + '\n  ]\n}\n')
        write(catalog.ROOT / 'docs/VERIFICATION_CATALOG.md', catalog.markdown(document))
    print(f'{len(rows)} assessments visible; {counts}; no current passes imported, no tests executed')


if __name__ == '__main__':
    main()
