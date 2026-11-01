#!/usr/bin/env python3
"""Generate reviewed Kani bindings from the catalog; execute no proofs."""
import argparse
import fcntl
import json
from pathlib import Path
import tempfile
import verification_kani_bindings as bindings

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    document = bindings.build(json.loads((ROOT / 'verification/catalog.json').read_text())['entries'])
    path = ROOT / 'verification/kani-checks.json'
    text = json.dumps(document, indent=2) + '\n'
    if not args.write:
        if json.loads(path.read_text()) != document:
            raise ValueError('Kani bindings changed; review and regenerate, do not rerun proofs')
    else:
        lock = ROOT / 'verification/.runner/lock'
        lock.parent.mkdir(parents=True, exist_ok=True)
        with lock.open('a+') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if not path.exists() or path.read_text() != text:
                with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as output:
                    output.write(text)
                    temporary = Path(output.name)
                temporary.replace(path)
    print(f'{len(document["checks"])} scoped Kani bindings; no proofs executed')


if __name__ == '__main__':
    main()
