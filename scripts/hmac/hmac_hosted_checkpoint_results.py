"""Follow failed checkpoint Result bytes through worker-only result transport.

This does not qualify the later host output transaction or callee internals.
"""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax

require, V, L = common.require, syntax.VALUE, common.LABEL
ALL = frozenset(range(256))


def result_slot(checkpoints):
    m, f = checkpoints.m, checkpoints.flow
    candidates = [name for name, (rhs, _) in m.defs.items()
                  if re.match(r'load ptr, ptr ' + re.escape(f.job) + ',', rhs)]
    require(len(candidates) == 1, 'checkpoint result capture population')
    pointer = candidates[0]
    uses = [line.split(', !', 1)[0] for lines in m.graph.values() for line in lines
            if pointer in re.findall(V, line)]
    # The worker's borrowed Result has exactly one capture load, the existing
    # job-null guard, and one two-byte write. No second load, hidden alias,
    # memcpy, escape, or subsequent overwrite may evade the byte-flow walk.
    expected = (re.escape(pointer) + r' = load ptr, ptr ' + re.escape(f.job) + r', align 8',
                V + r' = icmp eq ptr ' + re.escape(pointer) + ', null',
                r'store i16 ' + V + ', ptr ' + re.escape(pointer) + ', align 1')
    require(len(uses) == 3 and all(sum(bool(re.fullmatch(pattern, line)) for line in uses) == 1
                                  for pattern in expected), 'checkpoint result pointer alias/escape/overwrite')
    return pointer


def byte(value, known):
    if re.fullmatch(r'-?\d+', value):
        return frozenset({int(value) & 255})
    return known.get(value, ALL)


def evaluate(rhs, known, predecessor):
    phi = re.fullmatch(r'phi i(?:8|16) (.*)', rhs)
    if phi:
        entries = re.findall(r'\[ (' + V + r'|-?\d+|undef|poison), %' + L + r' \]', phi[1])
        selected = [value for value, label in entries if label == predecessor]
        require(len(selected) == 1, 'checkpoint result phi predecessor changed')
        return byte(selected[0], known)
    extend = re.fullmatch(r'zext i8 (' + V + ') to i16', rhs)
    if extend:
        return byte(extend[1], known)
    shift = re.fullmatch(r'shl(?: nuw)? i16 (' + V + '), 8', rhs)
    if shift:
        return frozenset({0})  # Only the Result discriminator (low byte).
    either = re.fullmatch(r'or(?: disjoint)? i16 (' + V + r'), (' + V + ')', rhs)
    if either:
        return frozenset(a | b for a in byte(either[1], known) for b in byte(either[2], known))
    return ALL


def walk(checkpoints, point, success):
    m, f = checkpoints.m, checkpoints.flow
    aggregate, discriminator, good, bad = checkpoints.guards[point]
    values = frozenset({checkpoints.ok & 255}) if success else ALL - {checkpoints.ok & 255}
    normal = f.returned(point)[0]
    queue = [(good if success else bad, normal, {discriminator: values}, False)]
    seen, stores = set(), 0
    result_pointer = result_slot(checkpoints)
    while queue:
        block, predecessor, known, stored = queue.pop()
        key = block, predecessor, tuple(sorted(known.items())), stored
        if key in seen:
            continue
        seen.add(key)
        require(len(seen) < 2000, 'checkpoint error continuation exceeds bound')
        lines = m.graph[block]
        # PHIs are parallel assignments, evaluated in the predecessor environment.
        incoming = dict(known)
        for index, line in enumerate(lines):
            at = block, index
            definition = re.match('(' + V + ') = (.*)', line)
            if definition:
                name, rhs = definition.groups()
                rhs = rhs.split(', !', 1)[0]
                extract = re.fullmatch(r'extractvalue \{ i8, i8 \} ' + re.escape(aggregate) + ', 0', rhs)
                known[name] = values if extract else evaluate(rhs, incoming if rhs.startswith('phi ') else known, predecessor)
            store = re.match(r'store i(8|16) (' + V + r'|-?\d+), ptr ' + re.escape(result_pointer) + ',', line)
            if store:
                actual = byte(store[2], known)
                require(actual == values,
                        'checkpoint result can be forged into worker success/failure')
                require(not stored, 'checkpoint continuation stores result twice')
                stored = True
                stores += 1
                checkpoints.points.add(at)
            if line.startswith(('br ', 'switch ', 'to label ')):
                text = '\n'.join(lines[index:]) if line.startswith('switch ') else line
                edges = re.findall(r'label %' + L, text)
                if line.startswith('to label '):
                    # An unwinding cleanup signals the separate job panic bit,
                    # not this Result. Its lifecycle is checked by the owner
                    # cleanup walker; this proof follows normally returned errors.
                    edges = edges[:1]
                queue.extend((edge, block, dict(known), stored) for edge in edges)
                break
            if line.startswith('ret '):
                require(stored, 'normal checkpoint continuation omits worker result')
                break
            if line == 'unreachable':
                # Fatal paths do not promise a result or erasure. Existing
                # lifetime/cleanup walkers validate exact fatal callees.
                break
    require(stores, 'vacuous checkpoint result transport')


def check(checkpoints):
    for point in checkpoints.guards:
        walk(checkpoints, point, False)
    walk(checkpoints, checkpoints.post, True)
