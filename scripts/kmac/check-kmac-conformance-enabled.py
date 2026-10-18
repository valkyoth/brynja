#!/usr/bin/env python3
"""Require each production method-set rejection under unified test features."""
import json
from pathlib import Path
import sys


def validate(output, source):
    expected = {line.strip() for line in source.splitlines() if line.strip().startswith('let _ = ')}
    if len(expected) != 52:
        raise ValueError('production conformance probe population changed')
    actual = set()
    for line in output.splitlines():
        item = json.loads(line)
        if item.get('reason') != 'compiler-message':
            continue
        message = item['message']
        if message['level'] != 'error':
            continue
        if (message.get('code') or {}).get('code') != 'E0599':
            raise ValueError('unrelated compiler failure in conformance gate')
        for span in message['spans']:
            if span['is_primary']:
                actual.update(row['text'].strip() for row in span['text'])
    if actual != expected:
        raise ValueError('missing or unexpected production conformance rejection')


if __name__ == '__main__':
    validate(Path(sys.argv[1]).read_text(),
             Path('assurance/kmac-conformance-rejected/src/enabled.rs').read_text())
    print('Enabled conformance feature rejects all 52 production method probes')
