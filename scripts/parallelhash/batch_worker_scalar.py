"""Rust 1.98 Arm abort: allocation-bound scalar Storage argument provenance.

Recognize the original 256-byte-slot allocation and the empty/allocated base
phi independently of cleanup operands. Follow their unchanged SSA values to
post-spawn clear calls. Valid Rust Vec/LLVM and finish_grow contracts are assumed;
this is not an allocator, zero-initialization, joining or machine-code proof.
"""
import re
from collections import deque

import batch_worker_provenance as provenance
from batch_worker_provenance import cfg, header, inline, require

V = cfg.VALUE
GROW = r'_RNvMs5_NtCs\w+_5alloc7raw_vecNtB5_11RawVecInner11finish_growCs\w+_24brynja_hash_parallel_std'


def dominators(blocks, predecessors):
    dom = {b: ({b} if b == 'start' else set(blocks)) for b in blocks}
    changed = True
    while changed:
        changed = False
        for b in blocks:
            if b == 'start':
                continue
            require(predecessors[b], 'reachable scalar coordinator block')
            value = {b} | set.intersection(*(dom[p] for p in predecessors[b]))
            if value != dom[b]:
                dom[b], changed = value, True
    return dom


def bindings(blocks, edges, predecessors):
    definitions = {provenance.result(line): (b, i, line) for b, lines in blocks.items()
                   for i, line in enumerate(lines) if provenance.result(line)}
    pattern = (r'call fastcc void @' + GROW + r'\(ptr noalias nofree noundef align 8 captures\(none\) '
               r'dereferenceable\(24\) (' + V + r'), i64 0, ptr nonnull inttoptr \(i64 1 to ptr\), '
               r'i64 noundef (' + V + r'), i64 noundef range\(i64 1, 9\) 1, '
               r'i64 noundef range\(i64 24, 257\) 256\)(?: #\d+)?')
    calls = [(b, i, m) for b, lines in blocks.items() for i, line in enumerate(lines)
             if (m := re.fullmatch(pattern, line))]
    require(len(calls) == 1, 'one original scalar 256-byte-slot allocation')
    grow_block, grow_index, call = calls[0]
    owner, width = call.groups()
    require(definitions[owner][0] == 'start' and definitions[owner][2] ==
            owner + ' = alloca [24 x i8], align 8', 'original allocation-result owner')
    width_block, width_index, width_line = definitions[width]
    require(re.fullmatch(re.escape(width) + r' = tail call noundef i64 @llvm.umin.i64\(i64 ' +
                         V + r', i64 ' + V + r'\)', width_line), 'original full slot-count definition')
    lines = blocks[grow_block]
    require(grow_index == 1 and len(lines) == 5 and lines[0] ==
            'call void @llvm.lifetime.start.p0(ptr nonnull ' + owner + ')', 'closed allocation-result entry')
    tag = re.fullmatch('(' + V + r') = load i64, ptr ' + re.escape(owner) + r', align 8', lines[2])
    require(tag is not None, 'allocation result discriminant')
    bit = re.fullmatch('(' + V + r') = trunc nuw i64 ' + re.escape(tag[1]) + r' to i1', lines[3])
    require(bit is not None and edges[grow_block][0] == 'branch' and
            lines[4].startswith('br i1 ' + bit[1] + ', '), 'allocation success branch')
    error_block, success_block = edges[grow_block][1]
    success = blocks[success_block]
    address = re.fullmatch('(' + V + r') = getelementptr inbounds nuw i8, ptr ' +
                           re.escape(owner) + r', i64 8', success[0])
    require(address is not None, 'allocation base field offset')
    loaded = re.fullmatch('(' + V + r') = load ptr, ptr ' + re.escape(address[1]) + r', align 8', success[1])
    require(loaded is not None and success[2] ==
            'call void @llvm.lifetime.end.p0(ptr nonnull ' + owner + ')', 'unchanged allocation base load')
    end = 'call void @llvm.lifetime.end.p0(ptr nonnull ' + owner + ')'
    allowed = {lines[0], lines[1], lines[2], success[0], success[1], end}
    for block_lines in blocks.values():
        for line in block_lines:
            if set(re.findall(V, cfg.operation(line))) & {owner, address[1]}:
                require(line in allowed, 'allocation-result address escape or overwrite')
    roots = [(b, i, re.fullmatch(r'(%storage[\w.]+) = phi ptr (.*)', line))
             for b, block_lines in blocks.items() for i, line in enumerate(block_lines)
             if re.fullmatch(r'%storage[\w.]+ = phi ptr .*', line)]
    require(len(roots) == 1, 'one scalar Storage base phi')
    base_block, base_index, match = roots[0]
    base = match[1]
    pairs = re.findall(r'\[ ([^\[\]]+), %(' + cfg.LABEL + r') \]', match[2])
    allocated = [b for value, b in pairs if value == loaded[1]]
    require(len(pairs) == 2 and len(allocated) == 1 and
            ('inttoptr (i64 1 to ptr)', width_block) in pairs, 'exact allocated/empty base alternatives')
    zero = re.fullmatch('(' + V + r') = icmp eq i64 ' + re.escape(width) + ', 0', blocks[width_block][-2])
    require(zero is not None and blocks[width_block][-1] ==
            f'br i1 {zero[1]}, label %{base_block}, label %{grow_block}', 'zero width exclusively selects empty base')
    dom = dominators(blocks, predecessors)
    require(predecessors[grow_block] == {width_block} and predecessors[success_block] == {grow_block} and
            grow_block in dom[success_block] and success_block in dom[allocated[0]] and
            error_block not in dom[allocated[0]], 'allocated base arrives through successful allocation')
    return (base, width), ((base_block, base_index), (width_block, width_index))


def inspect(body, clear):
    blocks, edges, predecessors = cfg.parse(body)
    roots, sites = bindings(blocks, edges, predecessors)
    def transfer(block, active, facts, validate=False):
        known, checked = [set(f) for f in facts], 0
        for index, line in enumerate(blocks[block]):
            dest = provenance.result(line)
            if not cfg.operation(line).startswith('phi '):
                for field in known:
                    field.discard(dest)
            for field, site in enumerate(sites):
                if (block, index) == site:
                    require(not active, 'no scalar Storage reinitialization after spawn')
                    known[field].add(roots[field])
            if re.fullmatch(inline.SPAWN, cfg.callee(line) or ''):
                active = True
                require(all(root in field for root, field in zip(roots, known)), 'initialized original scalar owner at spawn')
            if active and cfg.callee(line) == clear:
                if validate:
                    args = header.clear_arguments(line, clear)
                    require(all(arg in field for arg, field in zip(args, known)), 'unchanged scalar buffer/count to clear')
                checked += 1
        return active, tuple(frozenset(f) for f in known), checked
    states = {('start', False): (frozenset(), frozenset())}
    pending, updates = deque(states), 0
    while pending:
        block, active = key = pending.popleft()
        active, outgoing, _ = transfer(block, active, states[key])
        for successor in set(edges[block][1]):
            incoming = provenance.phis(blocks[successor], block, outgoing)
            key = successor, active
            merged = tuple(a & b for a, b in zip(states[key], incoming)) if key in states else incoming
            if key not in states or merged != states[key]:
                states[key] = merged
                pending.append(key)
                updates += 1
                require(updates <= 100000, 'bounded scalar provenance fixed point')
    checked = sum(transfer(b, active, facts, True)[2] for (b, active), facts in states.items())
    require(checked >= 2, 'non-vacuous scalar normal/error argument checks')
    return len(states), checked


def check(row, panic):
    require(panic == 'abort', 'reviewed scalar compiler profile')
    body, clear, drop, _ = inline.check(row, panic)
    require(drop is None, 'fully inlined scalar cleanup')
    return inspect(body, clear)


def mutations(row, panic):
    stats = check(row, panic)
    body, clear, _, reach = inline.check(row, panic)
    blocks, edges, predecessors = cfg.parse(body)
    roots, sites = bindings(blocks, edges, predecessors)
    changes = []
    for block, index in sorted(reach[2]):
        line = blocks[block][index]
        base, length = header.clear_arguments(line, clear)
        for changed in (line.replace('i64 ' + length + ')', 'i64 0)'),
                        '%short_count = sub i64 ' + length + ', 1\n' + line.replace('i64 ' + length + ')', 'i64 %short_count)'),
                        '%shifted_base = getelementptr i8, ptr ' + base + ', i64 256\n' +
                        line.replace('ptr nonnull ' + base + ',', 'ptr nonnull %shifted_base,')):
            changes.append(provenance.replace_in_block(body, block, line, changed))
    block, index = sites[0]
    line = blocks[block][index]
    changes.append(provenance.replace_in_block(body, block, line, line.replace('inttoptr (i64 1 to ptr)', 'null')))
    changes.append(body.replace('i64 noundef ' + roots[1] + ', i64 noundef range(i64 1, 9) 1',
                                'i64 noundef 0, i64 noundef range(i64 1, 9) 1'))
    for changed in changes:
        require(changed != body, 'non-vacuous scalar argument mutation')
        try:
            inspect(changed, clear)
        except ValueError:
            continue
        raise AssertionError('scalar argument regression survived')
    return *stats, len(changes)
