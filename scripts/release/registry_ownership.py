"""Read-only crates.io identity checks for first publications and resumed uploads."""
import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def lookup(path):
    req = Request('https://crates.io/api/v1/crates/' + path,
                  headers={'User-Agent': 'brynja-release (https://github.com/valkyoth/brynja)'})
    try:
        with urlopen(req, timeout=20) as response:
            payload = json.load(response)
            if not isinstance(payload, dict):
                raise ValueError(f'invalid registry response for {path}')
            return payload
    except HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def owners(name):
    rows = (lookup(name + '/owners') or {}).get('users')
    if (not isinstance(rows, list) or not rows or any(not isinstance(r, dict)
            or type(r.get('id')) is not int or r.get('kind') not in ('user', 'team') for r in rows)):
        raise ValueError(f'cannot establish registry owners for {name}')
    return {(r['kind'], r['id']) for r in rows}


def available(name):
    if lookup(name) is not None:
        raise ValueError(f'first-publication name already exists: {name}; stop and reconcile')


def indexed(name, version, trusted):
    row = (lookup(f'{name}/{version}') or {}).get('version') or {}
    if (not isinstance(row, dict) or row.get('crate') != name
            or row.get('num') != version or row.get('yanked') is not False
            or owners(name) != trusted):
        raise ValueError(f'cannot confirm project ownership and active {name} {version}; stop')


def first_publications(plan, steps):
    new = {name: row['version'] for name, row in plan['crates'].items()
           if row.get('change') == 'initial' and row.get('publish')}
    trusted = owners('brynja') if new else set()
    for name, version in new.items():
        if name in steps:
            available(name)
        else:
            # --start-at skips uploads, not identity checks on their prerequisites.
            indexed(name, version, trusted)
    return new, trusted
