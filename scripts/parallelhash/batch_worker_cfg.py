"""Closed LLVM CFG extraction for the emitted inlined worker coordinator.

This validates control-flow structure, not arithmetic or LLVM instruction
semantics. Non-terminating paths are not completion/erasure evidence.
"""
import re
from collections import Counter
from batch_cleanup_flow import require

LABEL = r'(?:[\w.-]+|"[^"\n]+")'
VALUE = r'%[\w.-]+'
SYMBOL = r'(?:[\w.$]+|"[^"\n]+")'


def operation(line):
    return re.sub(r'^' + VALUE + r' = ', '', line)


def callee(line):
    op = operation(line)
    if not re.match(r'(?:(?:tail|musttail|notail) )?(?:call|invoke)\b', op):
        return None
    match = re.search('@(' + SYMBOL + r')\(', op)
    return match[1].strip('"') if match else None


def terminal(line):
    op = operation(line)
    if op in ('ret void', 'unreachable') or re.fullmatch(r'resume \{ ptr, i32 \} ' + VALUE, op):
        return op.split()[0], ()
    jump = re.fullmatch(r'br label %(' + LABEL + ')', op)
    if jump:
        return 'jump', (jump[1],)
    branch = re.fullmatch(r'br i1 (?:' + VALUE + r'|true|false), label %(' + LABEL + r'), label %(' + LABEL + ')', op)
    if branch:
        return 'branch', branch.groups()
    invoke = re.fullmatch(r'invoke .+ to label %(' + LABEL + r') unwind label %(' + LABEL + ')', op)
    if invoke:
        return 'invoke', invoke.groups()
    switch = re.fullmatch(r'switch (i\d+) (?:' + VALUE + r'|-?\d+), label %(' + LABEL + r') \[ (.*) \]', op)
    if switch:
        case = switch[1] + r' (-?\d+), label %(' + LABEL + ')'
        pairs = re.findall(case, switch[3])
        require(pairs and ' '.join(f'{switch[1]} {v}, label %{b}' for v, b in pairs) == switch[3], 'complete switch cases')
        require(len({v for v, _ in pairs}) == len(pairs), 'unique switch values')
        return 'switch', (switch[2], *(b for _, b in pairs))
    return None


def parse(body):
    blocks, current, pending = {}, None, ''
    for raw in body.splitlines()[1:]:
        line = raw.split(';', 1)[0].strip().split(', !', 1)[0]
        if not line or line == '}':
            continue
        label = re.fullmatch('(' + LABEL + '):', line)
        if label:
            require(not pending and label[1] not in blocks, 'unique block with no interrupted terminator')
            current = label[1]
            blocks[current] = []
            continue
        require(current is not None, 'instruction within coordinator block')
        if pending:
            pending += ' ' + line
            if line != ']' and not line.startswith('to label '):
                continue
            line, pending = pending, ''
        elif operation(line).startswith('invoke ') or line.startswith('switch '):
            pending = line
            continue
        blocks[current].append(line)
    require(not pending and blocks and next(iter(blocks)) == 'start', 'complete coordinator CFG entry')
    predecessors = {block: set() for block in blocks}
    edges = {}
    for block, lines in blocks.items():
        require(lines and terminal(lines[-1]) is not None, 'recognized coordinator terminator: ' + block)
        require(all(terminal(line) is None for line in lines[:-1]), 'no hidden coordinator terminator: ' + block)
        for line in lines[:-1]:
            require(not re.match(r'(?:br|switch|indirectbr|callbr|invoke|ret|resume|unreachable|catchswitch|catchret|cleanupret)\b',
                                 operation(line)), 'unsupported or malformed control transfer')
        require(not any(re.search(r'\basm\b', operation(line)) for line in lines), 'no opaque assembly control flow')
        edges[block] = terminal(lines[-1])
        for successor in edges[block][1]:
            require(successor in blocks, 'existing coordinator successor')
            predecessors[successor].add(block)
    require(not predecessors['start'], 'entry has no predecessors')
    for block, lines in blocks.items():
        past_phi = False
        for line in lines:
            phi = re.fullmatch(VALUE + r' = phi (?:ptr|i\d+|\{ ptr, i32 \}) (.*)', line)
            if not phi:
                require(not operation(line).startswith('phi '), 'recognized coordinator phi type')
                past_phi = True
                continue
            require(not past_phi, 'phis precede instructions')
            pairs = re.findall(r'\[ ([^\[\]\n]+), %(' + LABEL + r') \]', phi[1])
            require(pairs and ', '.join(f'[ {v}, %{b} ]' for v, b in pairs) == phi[1], 'complete phi inputs')
            expected = Counter(p for p, (_, targets) in edges.items() for target in targets if target == block)
            require(Counter(b for _, b in pairs) == expected and
                    all(len({v for v, b in pairs if b == p}) == 1 for p in expected), 'exact phi predecessor edges')
    return blocks, edges, predecessors


def noreturn_symbols(ir):
    attributes = {m[1] for m in re.finditer(r'^attributes #(\d+) = \{ ([^\n]+) \}', ir, re.M)
                  if re.search(r'\bnoreturn\b', m[2])}
    symbols = set()
    for line in ir.splitlines():
        if not line.startswith(('declare ', 'define ')):
            continue
        symbol = re.search('@(' + SYMBOL + r')\(', line)
        groups = re.findall(r'#(\d+)\b', line)
        if symbol and any(group in attributes for group in groups):
            symbols.add(symbol[1].strip('"'))
    return symbols


def unreachable_is_terminal(block, blocks, edges, predecessors, noreturn):
    lines = blocks[block]
    if len(lines) > 1:
        return callee(lines[-2]) in noreturn
    return bool(predecessors[block]) and all(
        (edges[p][0] == 'switch' and edges[p][1][0] == block and block not in edges[p][1][1:]) or
        (edges[p][0] == 'invoke' and edges[p][1][0] == block and callee(blocks[p][-1]) in noreturn)
        for p in predecessors[block])
