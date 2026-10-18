#!/usr/bin/env python3
"""Require each production method-set rejection under unified test features."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'repository'))
from facade_conformance_cases import CONSTRUCT, FIXED, SCOPE, STATES, XOF


def probes():
    """Use the facade's exhaustive method inventory, not a sample or count."""
    result = []
    for prefix, scoped in (('brynja_mac_kmac', False),
                           ('brynja_mac_kmac::execution', False),
                           ('brynja_mac_kmac::hardened_in_place', True),
                           ('scoped_execution', True)):
        for name in STATES:
            methods = XOF if 'Xof' in name else FIXED
            if not scoped:
                methods = CONSTRUCT + methods
            result.extend(f'let _ = {prefix}::{name}::{method};' for method in methods)
            if scoped:
                scope = SCOPE + (('with_bits_and_scratch_conformance',)
                                 if prefix == 'scoped_execution' else ())
                result.extend(f'let _ = {prefix}::{name}Workspace::{method};' for method in scope)
    return result


def source_text():
    return ('//! Production method-set negatives with leaf conformance enabled.\n\n'
            'use brynja_mac_kmac::hardened_in_place::accelerated as scoped_execution;\n\n' +
            '\n'.join(f'fn reject_{index}() {{\n    {probe}\n}}\n'
                      for index, probe in enumerate(probes())))


def validate(output, source):
    expected = set(probes())
    if source != source_text():
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
    print(f'Enabled conformance feature rejects all {len(probes())} production method probes')
