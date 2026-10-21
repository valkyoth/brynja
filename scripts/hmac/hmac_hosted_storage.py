"""Hosted retained/transfer allocation lifetimes, not physical-copy erasure."""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_execution_drop as destruction

require, VALUE = common.require, syntax.VALUE


def after_end(model, end, start, uses):
    """A loop may restart a temporary's lifetime before its next use."""
    pending, seen = [(end[0], end[1] + 1)], set()
    while pending:
        label, index = pending.pop()
        if (label, index) in seen:
            continue
        seen.add((label, index))
        lines = model.graph[label]
        for offset in range(index, len(lines)):
            point = label, offset
            if point == start:
                break
            if point in uses:
                return True
        else:
            pending.extend((edge, 0) for edge in re.findall(
                r'label %' + common.LABEL, ' '.join(lines)))
    return False


def check(model, identity):
    roots = {model.owner}
    copies = {}
    for mode, point, dest, args in model.writes:
        if mode != 'copy' or not model.before(model.cut, point):
            continue
        source = model.pointer(syntax.operand(args[1]), point)
        if not source or source[0] != model.owner:
            continue
        destination = model.pointer(dest, point)
        extent = re.fullmatch(r'i64 (\d+)', args[2])
        allowed = {model.size}
        if model.compiled:
            allowed.add(destruction.layout(identity, 'static').engine)
        require(source == (model.owner, 0) and extent and int(extent[1]) in allowed
                and destination and destination[1] == 0 and destination[0] != model.owner
                and model.allocs[destination[0]] == int(extent[1]), 'retained transfer geometry changed')
        require(destination[0] not in copies, 'retained destination written by multiple transfers')
        copies[destination[0]] = point
        roots.add(destination[0])
    require(len(copies) >= 2, 'retained terminal transfers absent')
    aliases = {name for name in model.defs if (address := model.pointer(name)) and address[0] in roots}
    uses = {root: set() for root in roots}
    starts, ends = {root: [] for root in roots}, {root: [] for root in roots}

    def address(value):
        result = model.pointer(value)
        return result if result and result[0] in roots else None

    def use(value, size, point):
        result = address(value)
        if result:
            root, offset = result
            require(0 <= offset <= model.allocs[root] - size, 'retained access outside allocation')
            uses[root].add(point)

    for label, lines in model.graph.items():
        for index, line in enumerate(lines):
            point = label, index
            mentioned = set(re.findall(VALUE, line)) & aliases
            if not mentioned:
                continue
            definition = re.match('(' + VALUE + ') = (.*)', line)
            if definition and definition[1] in model.allocs:
                continue
            if definition and definition[2].startswith('getelementptr'):
                require(address(definition[1]), 'unreviewed retained pointer arithmetic')
                continue
            load = re.match('(' + VALUE + r') = load (ptr|i\d+), ptr (' + VALUE + '),', line)
            store = re.match(r'store (ptr|i\d+) (.+), ptr (' + VALUE + '),', line)
            if load:
                use(load[3], 8 if load[2] == 'ptr' else (int(load[2][1:]) + 7) // 8, point)
            elif store:
                require(mentioned == {store[3]}, 'retained pointer stored as value')
                use(store[3], 8 if store[1] == 'ptr' else (int(store[1][1:]) + 7) // 8, point)
            elif point in model.call_map:
                symbol, args = model.call_map[point]
                if symbol.startswith('llvm.lifetime.'):
                    require(symbol in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0'), 'unknown retained lifetime')
                    pointer = address(syntax.operand(args[-1]))
                    require(pointer and pointer[1] == 0, 'interior retained lifetime')
                    (starts if symbol == 'llvm.lifetime.start.p0' else ends)[pointer[0]].append(point)
                    continue
                for arg in args:
                    if arg.startswith('ptr '):
                        extent = re.search(r'dereferenceable\((\d+)\)', arg)
                        use(syntax.operand(arg), int(extent[1]) if extent else 1, point)
            else:
                require(False, 'unreviewed retained alias/escape: ' + line)
    for root in roots:
        require(len(starts[root]) == 1 and uses[root], 'missing/ambiguous retained lifetime start')
        require(all(model.before(starts[root][0], point) for point in uses[root]),
                'retained allocation used before lifetime start')
        for end in ends[root]:
            require(not after_end(model, end, starts[root][0], uses[root]),
                    'retained allocation used after lifetime end')
        if root != model.owner:
            require(all(point == copies[root] or model.before(copies[root], point) for point in uses[root]),
                    'retained transfer slot used before copy')
    return roots, copies, uses, starts, ends
