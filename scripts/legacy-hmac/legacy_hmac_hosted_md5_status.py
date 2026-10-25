"""Symbolic two-byte worker Result transport after MD5 checkpoint rejection.

Error payload bits retain their identity, not just their set of possible values.
Success/cancellation have no defined error payload. Host transactions remain
separate; existing envelope/lifecycle models qualify storage and unwind paths.
"""
import re

import legacy_hmac_hosted_md5_checkpoint as callee

V, L, require = callee.V, callee.L, callee.require
TOKEN = V + r'|-?\d+|undef|poison'
ERROR = tuple(('error', bit) for bit in range(8))


def literal(number, width):
    return tuple((number >> bit) & 1 for bit in range(width))


def value(token, known, width):
    if re.fullmatch(r'-?\d+', token):
        return literal(int(token), width)
    result = known.get(token)
    return result if isinstance(result, tuple) and len(result) == width else (None,) * width


def evaluate(rhs, known, incoming, predecessor):
    phi = re.fullmatch(r'phi i(8|16) (.*)', rhs)
    if phi:
        pairs = re.findall(r'\[ (' + TOKEN + '), %' + L + r' \]', phi[2])
        require(phi[2] == ', '.join('[ ' + item + ', %' + label + ' ]' for item, label in pairs),
                'MD5 checkpoint status phi has unparsed fields')
        selected = [item for item, label in pairs if label == predecessor]
        require(selected and len(set(selected)) == 1, 'MD5 checkpoint status phi predecessor changed')
        return value(selected[0], incoming, int(phi[1]))
    cast = re.fullmatch(r'zext i8 (' + TOKEN + ') to i16', rhs)
    if cast:
        return value(cast[1], known, 8) + (0,) * 8
    shift = re.fullmatch(r'shl(?: nuw| nsw)* i16 (' + TOKEN + '), 8', rhs)
    if shift:
        return (0,) * 8 + value(shift[1], known, 16)[:8]
    binary = re.fullmatch(r'(or|add)(?: disjoint| nuw| nsw)* i16 (' + TOKEN + '), (' + TOKEN + ')', rhs)
    if binary:
        left, right = value(binary[2], known, 16), value(binary[3], known, 16)
        # The compiler joins disjoint bytes using either or or add. Requiring a
        # known zero on one side at every bit excludes hidden overlap/carries.
        if not all(a == 0 or b == 0 for a, b in zip(left, right)):
            return None
        return tuple(b if a == 0 else a for a, b in zip(left, right))
    extract = re.fullmatch(r'extractvalue \{ i8, i8 \} (' + V + '), ([01])', rhs)
    if extract:
        aggregate = known.get(extract[1])
        return aggregate[int(extract[2])] if isinstance(aggregate, tuple) and len(aggregate) == 2 else None
    return None


def walk(model, envelope, block, predecessor, known, code, payload=None, offset=0):
    pointer = envelope['loads'][32][1]
    expected = literal(code, 8)
    queue = [(block, offset, predecessor, known, False, frozenset())]
    seen, stores, points = set(), 0, set()
    while queue:
        block, offset, predecessor, known, stored, path = queue.pop()
        require(block not in path, 'MD5 checkpoint rejection continuation cycles')
        path = path | {block}
        key = block, offset, predecessor, tuple(sorted(known.items())), stored, path
        if key in seen:
            continue
        seen.add(key)
        require(len(seen) < 1000, 'MD5 checkpoint error continuation exceeds bound')
        incoming = dict(known)
        for index, line in enumerate(model.graph[block][offset:], offset):
            define = re.match('(' + V + ') = (.*)', line)
            if define:
                known[define[1]] = evaluate(define[2].split(', !', 1)[0], known, incoming, predecessor)
            write = re.match('store i16 (' + TOKEN + '), ptr ' + re.escape(pointer) + ',', line)
            if write:
                actual = value(write[1], known, 16)
                require(actual[:8] == expected and (payload is None or actual[8:] == payload) and not stored,
                        'MD5 checkpoint error/status payload lost, forged or overwritten')
                require(envelope['result'] == (block, index), 'MD5 checkpoint uses another Result store')
                points.add((block, index))
                stored, stores = True, stores + 1
            if line.startswith(('br ', 'switch ', 'to label ')):
                rows = model.graph[block]
                text = '\n'.join(rows[index:]) if line.startswith('switch ') else line
                edges = re.findall('label %' + L, text)
                if line.startswith('to label '):
                    edges = edges[:1]  # Normally returned errors; unwind has a separate panic bit.
                require(edges, 'MD5 checkpoint continuation has no edges')
                queue.extend((edge, 0, block, dict(known), stored, path) for edge in edges)
                break
            if line.startswith('ret '):
                require(stored, 'MD5 checkpoint return omits Result')
                break
            if line == 'unreachable':
                break
        else:
            require(False, 'MD5 checkpoint continuation falls off block')
    require(stores, 'vacuous MD5 checkpoint result transport')
    return points
