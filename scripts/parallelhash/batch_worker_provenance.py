"""Must-equality analysis of post-spawn, memory-backed Storage clear arguments.

At a fixed point, each clear must receive values equal to the original header's
base/live length. Header writes/escapes after spawn are forbidden. Equalities are
intersected at joins, phis use predecessor-specific facts simultaneously, and SSA
redefinitions kill stale loop-iteration facts. Valid emitted LLVM, Vec invariants
and reviewed callee contracts are assumptions. Scalar-replaced headers and
machine lowering are outside this check, not successful empty qualifications.
"""
import re
from collections import deque

import batch_worker_inline as inline
import batch_worker_cfg as cfg
import batch_worker_header as header
from batch_cleanup_flow import require


def result(line):
    match = re.match('(' + cfg.VALUE + r') = ', line)
    return match[1] if match else None


def phis(lines, predecessor, facts):
    parsed = []
    for line in lines:
        if not cfg.operation(line).startswith('phi '):
            break
        values = re.findall(r'\[ ([^\[\]\n]+), %(' + cfg.LABEL + r') \]', line)
        selected = {value for value, source in values if source == predecessor}
        require(len(selected) == 1, 'one phi value for this predecessor')
        parsed.append((result(line), selected.pop()))
    destinations = {dest for dest, _ in parsed}
    return tuple(frozenset((known - destinations) | {dest for dest, value in parsed if value in known})
                 for known in facts)


def transfer(lines, active, facts, actions, clear, validate=False):
    known = [set(field) for field in facts]
    checked = 0
    for index, line in enumerate(lines):
        if cfg.operation(line).startswith('phi '):
            continue  # Already evaluated on incoming edges, simultaneously.
        dest = result(line)
        for field in known:
            field.discard(dest)
        kind, detail = actions[index]
        if re.fullmatch(inline.SPAWN, cfg.callee(line) or ''):
            active = True
        require(not active or kind not in ('store', 'grow', 'start'),
                'original worker header changes after spawn')
        if kind == 'load' and detail in (8, 16):
            known[detail // 8 - 1].add(dest)
        elif kind == 'store' and detail[0] in (8, 16):
            known[detail[0] // 8 - 1] = {detail[1]}
        elif kind in ('grow', 'start', 'end'):
            known = [set(), set()]
        if active and cfg.callee(line) == clear:
            args = header.clear_arguments(line, clear)
            if validate:
                require(all(value in field for value, field in zip(args, known)),
                        'inlined clear does not receive original Vec base/live length: ' + line)
            checked += 1
        elif active and kind == 'drop':
            checked += 1
    return active, tuple(frozenset(field) for field in known), checked


def inspect(body, clear, drop):
    blocks, edges, _ = cfg.parse(body)
    root, fields = header.header(blocks)
    actions = {b: [header.uses(line, root, fields, drop) for line in lines] for b, lines in blocks.items()}
    # A newly reached state starts with its first incoming facts; every further
    # edge can only remove facts. Validate calls AFTER convergence, never using
    # an optimistic first predecessor as proof of all paths.
    empty = (frozenset(), frozenset())
    states, pending = {('start', False): empty}, deque([('start', False)])
    updates = 0
    while pending:
        block, active = key = pending.popleft()
        active, outgoing, _ = transfer(blocks[block], active, states[key], actions[block], clear)
        for successor in set(edges[block][1]):
            incoming = phis(blocks[successor], block, outgoing)
            next_key = successor, active
            merged = (tuple(a & b for a, b in zip(states[next_key], incoming))
                      if next_key in states else incoming)
            if next_key not in states or merged != states[next_key]:
                states[next_key] = merged
                pending.append(next_key)
                updates += 1
                require(updates <= 100000, 'bounded provenance fixed point')
    checked = sum(transfer(blocks[b], active, facts, actions[b], clear, True)[2]
                  for (b, active), facts in states.items())
    require(checked >= 2, 'non-vacuous normal/error argument checks')
    return len(states), checked


def check(row, panic):
    body, clear, drop, _ = inline.check(row, panic)
    return inspect(body, clear, drop)


def replace_in_block(body, block, line, replacement):
    headers = list(re.finditer('^(' + cfg.LABEL + '):', body, re.M))
    positions = [i for i, item in enumerate(headers) if item[1] == block]
    require(len(positions) == 1, 'unique argument mutation block')
    position = positions[0]
    start = headers[position].end()
    end = headers[position + 1].start() if position + 1 < len(headers) else len(body)
    segment = body[start:end]
    require(segment.count(line) == 1, 'unique argument mutation line')
    return body[:start] + segment.replace(line, replacement) + body[end:]


def mutations(row, panic):
    body, clear, drop, reach = inline.check(row, panic)
    stats = inspect(body, clear, drop)
    blocks, _, _ = cfg.parse(body)
    root, fields = header.header(blocks)
    length_address = next(address for address, offset in fields.items() if offset == 16)
    count = 0
    for block, index in sorted(reach[2]):
        line = blocks[block][index].split(' to label ', 1)[0]
        edits = ['store i64 0, ptr ' + length_address + ', align 8\n' + line]
        if cfg.callee(line) == clear:
            base, length = header.clear_arguments(line, clear)
            edits.extend((line.replace('i64 ' + length + ')', 'i64 0)'),
                          '%short_worker_length = sub i64 ' + length + ', 1\n' +
                          line.replace('i64 ' + length + ')', 'i64 %short_worker_length)'),
                          '%shifted_worker_base = getelementptr i8, ptr ' + base + ', i64 256\n' +
                          line.replace('ptr nonnull ' + base + ',', 'ptr nonnull %shifted_worker_base,')))
        else:
            edits.append('%foreign_worker_owner = alloca [24 x i8], align 8\n' +
                         line.replace(root, '%foreign_worker_owner'))
        for changed in edits:
            try:
                inspect(replace_in_block(body, block, line, changed), clear, drop)
            except ValueError:
                count += 1
            else:
                raise AssertionError('inlined argument mutation survived: ' + changed)
    require(count >= 6, 'normal/error provenance mutations exercised')
    return *stats, count
