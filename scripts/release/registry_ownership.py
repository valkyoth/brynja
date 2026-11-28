"""Read-only crates.io identity checks for first publications and resumed uploads."""
import json
import registry_transport as transport


def lookup(path):
    def decode(response):
        payload = json.load(response)
        if not isinstance(payload, dict):
            raise ValueError(f'invalid registry response for {path}')
        return payload
    return transport.read('https://crates.io/api/v1/crates/' + path, decode)


def owners(name):
    rows = (lookup(name + '/owners') or {}).get('users')
    if (not isinstance(rows, list) or not rows or any(not isinstance(r, dict)
            or type(r.get('id')) is not int or r.get('kind') not in ('user', 'team') for r in rows)):
        raise ValueError(f'cannot establish registry owners for {name}')
    return {(r['kind'], r['id']) for r in rows}


def available(name):
    if lookup(name) is not None:
        raise ValueError(f'first-publication name already exists: {name}; stop and reconcile')


def confirmed(name, version, trusted, response, *, just_uploaded=False):
    row = (response or {}).get('version')
    if (not isinstance(row, dict) or row.get('crate') != name
            or row.get('num') != version or row.get('yanked') is not False):
        raise ValueError(f'cannot confirm project ownership and active {name} {version}; stop')
    current = owners(name)
    if current == trusted:
        return row
    # A new name initially belongs to its uploader. Allow this bootstrap only
    # following this process's successful upload, never for a name we skipped.
    if just_uploaded and len(current) == 1 and current < trusted and next(iter(current))[0] == 'user':
        print(f'{name}: verified trusted uploader; reconcile the remaining project owners '
              'and verify the full owner set before resuming or closing the release.')
        return row
    raise ValueError(f'cannot confirm project ownership and active {name} {version}; stop')


def indexed(name, version, trusted, *, just_uploaded=False):
    return confirmed(name, version, trusted, lookup(f'{name}/{version}'), just_uploaded=just_uploaded)


def inspect(name, entry, trusted):
    version = entry['version']
    response = lookup(f'{name}/{version}')
    if response is not None:
        return confirmed(name, version, trusted, response)
    if entry['change'] == 'initial':
        available(name)
    elif owners(name) != trusted:
        raise ValueError(f'cannot confirm project ownership of {name}; stop')
    return None
