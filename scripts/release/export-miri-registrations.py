#!/usr/bin/env python3
"""Explicitly translate existing Miri definitions; execute nothing."""
import argparse
import fcntl
import json
from pathlib import Path
import tempfile
import verification_miri_bindings as bindings

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    document = bindings.build(json.loads((ROOT / 'verification/catalog.json').read_text())['entries'])
    path = ROOT / 'verification/miri-checks.json'
    if not args.write:
        if json.loads(path.read_text()) != document:
            raise ValueError('Miri registration definitions changed; review and regenerate, do not rerun tests')
    else:
        lock = ROOT / 'verification/.runner/lock'
        lock.parent.mkdir(parents=True, exist_ok=True)
        with lock.open('a+') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            text = json.dumps({'schema': 1, 'groups': document['groups']}, indent=2).rstrip()[:-1].rstrip()
            text += ',\n  "checks": [\n' + ',\n'.join('    ' + json.dumps(c, separators=(',', ':')) for c in document['checks']) + '\n  ]\n}\n'
            if not path.exists() or path.read_text() != text:
                with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as output:
                    output.write(text)
                    temporary = Path(output.name)
                temporary.replace(path)
    print(f'{len(document["checks"])} scoped Miri registrations; no verification executed')


if __name__ == '__main__':
    main()
