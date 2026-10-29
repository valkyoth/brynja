"""Follow validated reuse origins without manufacturing a fresh execution."""


def execution(reader, record):
    chain, seen = [], set()
    while record['state'] == 'reused':
        origin = record['origin']
        key = (origin['receipt'], origin['index'])
        if key in seen or len(chain) >= 16:
            raise ValueError('dashboard reuse ancestry exceeds bound or cycles')
        seen.add(key)
        chain.append(origin)
        manifest, _, passed = reader.completed(origin['receipt'], allow_failed=True)
        previous = passed.get(origin['index'])
        if (previous is None or previous['log_sha256'] != record['log_sha256']
                or previous['log_bytes'] != record['log_bytes']):
            raise ValueError('dashboard reuse origin/log mismatch')
        record = previous
    if not chain or record['state'] != 'passed':
        raise ValueError('dashboard reuse lacks a validated original execution')
    return {'ended': record['ended'], 'execution_commit': manifest['sources']['head'],
            'execution_origin': chain[-1], 'reuse_chain': chain,
            'source_command_seconds': record['elapsed_seconds']}
