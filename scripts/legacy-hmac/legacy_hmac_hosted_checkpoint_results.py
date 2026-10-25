"""Narrow accelerated checkpoint status through actual worker Result writes.

This proves the low-byte success/error classification, not arbitrary error
payloads or the later host quarantine/output transaction. Primitive cleanup
unwind remains qualified by the existing retained-owner/envelope walkers.
"""
import re

import legacy_hmac_hosted_checkpoints as checkpoints

shared = checkpoints.shared.results
require, V, L = checkpoints.require, checkpoints.V, checkpoints.L


def walk(checked, block, predecessor, known, expected):
    model = checked.m
    pointer = shared.result_slot(checked)
    queue = [(block, predecessor, known, False)]
    seen, stores = set(), 0
    while queue:
        block, predecessor, known, stored = queue.pop()
        key = block, predecessor, tuple(sorted(known.items())), stored
        if key in seen:
            continue
        seen.add(key)
        require(len(seen) < 2000, 'accelerated checkpoint continuation exceeds bound')
        incoming = dict(known)
        for index, line in enumerate(model.graph[block]):
            definition = re.match('(' + V + ') = (.*)', line)
            if definition:
                name, rhs = definition.groups()
                rhs = rhs.split(', !', 1)[0]
                known[name] = shared.evaluate(rhs, incoming if rhs.startswith('phi ') else known, predecessor)
            store = re.match(r'store i16 (' + V + r'|-?\d+), ptr ' + re.escape(pointer) + ',', line)
            if store:
                require(shared.byte(store[1], known) == expected and not stored,
                        'accelerated checkpoint error/success classification lost or overwritten')
                stored, stores = True, stores + 1
                checked.points.add((block, index))
            if line.startswith(('br ', 'switch ', 'to label ')):
                rows = model.graph[block]
                text = '\n'.join(rows[index:]) if line.startswith('switch ') else line
                edges = re.findall(r'label %' + L, text)
                if line.startswith('to label '):
                    edges = edges[:1]
                queue.extend((edge, block, dict(known), stored) for edge in edges)
                break
            if line.startswith('ret '):
                require(stored, 'accelerated checkpoint continuation omits result')
                break
            if line == 'unreachable':
                break  # Fatal paths do not promise a normal result.
    require(stores, 'vacuous accelerated checkpoint result transport')
