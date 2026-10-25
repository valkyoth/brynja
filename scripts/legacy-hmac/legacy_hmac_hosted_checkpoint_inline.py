"""Actual inlined SHA-1 temporary-stream paths, without synthetic IR rewriting.

Stops at the cancellation load or rejected Result cleanup. Placement of all
checkpoints and propagation into the host transaction are separate obligations.
Executor-start failure/unwind owns no stream; primitive Drop is nonpanicking.
"""
import re

import legacy_hmac_hosted_checkpoint_flow as execution
import legacy_hmac_hosted_checkpoints as checkpoints

require, syntax, V, flow = execution.require, execution.syntax, execution.V, execution.flow


def check(model, incoming, transfer, target):
    starts = [(args, point) for symbol, args, point in model.calls if model.names.get(symbol) == execution.START]
    outlined = [(args, point) for symbol, args, point in model.calls
                if model.names.get(symbol) == checkpoints.owner(target) + '::sha1_compiled::worker::checkpoint']
    require(len(starts) + len(outlined) == 6, 'accelerated SHA-1 checkpoint population changed')
    # An outlined callee is checked separately. Inlining is compiler dependent;
    # this model checks every surviving start, not a fixed inlining count.
    visited_all, records = set(), []
    for args, point in starts:
        require(len(args) == 2 and model.pointer(syntax.operand(args[1]), point) == (transfer.owner, 0),
                'inlined checkpoint does not borrow the admitted executor')
        result = model.pointer(syntax.operand(args[0]), point)
        require(result and result[1] == 0 and model.allocs.get(result[0]) == 448,
                'inlined checkpoint Result storage changed')
        destinations = {model.pointer(syntax.operand(items[0]))[0]
                        for symbol, items, _ in model.calls if symbol == 'llvm.memcpy.p0.p0.i64'
                        and (source := model.pointer(syntax.operand(items[1]))) and source[0] == result[0]
                        and model.pointer(syntax.operand(items[0]))}
        require(len(destinations) == 1, 'inlined checkpoint Stream transfer missing/ambiguous')
        destination = destinations.pop()
        roots = {result[0], destination}
        require(len(roots) == 2 and model.allocs.get(destination) == 448,
                'inlined checkpoint Stream aliases Result/wrong extent')
        lifetime = [(symbol, items, site) for symbol, items, site in model.calls
                    if symbol.startswith('llvm.lifetime.')
                    and (address := model.pointer(syntax.operand(items[-1]))) and address[0] in roots]
        for root in roots:
            begin = [(items, site) for symbol, items, site in lifetime if symbol == 'llvm.lifetime.start.p0'
                     and model.pointer(syntax.operand(items[-1])) == (root, 0)]
            require(len(begin) == 1 and begin[0][1][0] == point[0] and model.before(begin[0][1], point),
                    'inlined checkpoint storage not live before start')
        visited = {point, *(site for symbol, _, site in lifetime if symbol == 'llvm.lifetime.start.p0')}
        if 'invoke ' in model.graph[point[0]][point[1]]:
            visited.add((point[0], point[1] + 1))
        exits = []
        for flag in (0, 1, 2):
            machine = execution.Machine('ptr %owner, ptr %cancel', model.graph, model.names, flag=flag)
            machine.memory = {root: [None] * 448 for root in roots}
            machine.live = set(roots)
            for name in model.defs:
                address = model.pointer(name)
                if address and address[0] in roots and model.before(model.defs[name][1], point):
                    machine.values[name] = address
            machine.values[syntax.operand(args[1])] = (('argument', 0), 0)
            # Bind the cancel pointer from the independently checked capture,
            # never from a candidate atomic-load address alone.
            # field() is the shared capture-provenance proof; reject all other
            # pointers when the real atomic instruction is visited below.
            for label, lines in model.graph.items():
                for line in lines:
                    atomic = re.search(r'load atomic i8, ptr (' + V + ') acquire, align 1', line)
                    if atomic:
                        incoming.field(atomic[1], 'ptr', 80)  # compiled capture adds its +8 shift
                        require(model.before(model.defs[atomic[1]][1], point),
                                'inlined cancellation capture read after start')
                        machine.values[atomic[1]] = (('argument', 1), 0)
            for symbol, items, site in lifetime:
                if symbol == 'llvm.lifetime.start.p0':
                    require(len(items) == 1 or len(items) == 2 and items[0] == 'i64 448',
                            'inlined checkpoint lifetime extent changed')
            machine.call(next(symbol for symbol, _, site in model.calls if site == point), args)
            start = (point[0], point[1] + 1)
            if 'invoke ' in model.graph[point[0]][point[1]]:
                edge = re.fullmatch('to label %' + flow.LABEL + ' unwind label %' + flow.LABEL,
                                    model.graph[point[0]][point[1] + 1].split(', !', 1)[0])
                require(edge, 'inlined checkpoint start invoke edges changed')
                start = (edge[1], 0)
            stop = lambda state, _site: state.cancelled or (flag == 2 and not state.live)
            end = machine.run(start, stop, allow_invoke=True)
            require(not machine.live and machine.dropped == machine.cancelled == (flag != 2),
                    'inlined checkpoint cleanup/result partition changed')
            if flag != 2:
                require(machine.reads and 'load atomic ' in model.graph[end[0]][end[1] - 1],
                        'inlined checkpoint continuation is not cancellation')
            exits.append(end)
            visited.update(machine.reads)
        require(exits[0] == exits[1] and exits[2] != exits[0], 'inlined checkpoint Result paths merged')
        # Reject all extra uses, escaping aliases, late writes or destructor
        # calls outside the interpreted paths, even if another projection would
        # otherwise ignore them. Address calculations alone carry no secret.
        for label, rows in model.graph.items():
            for index, line in enumerate(rows):
                refs = [name for name in re.findall(V, line)
                        if (address := model.pointer(name)) and address[0] in roots]
                if not refs:
                    continue
                if re.fullmatch(V + r' = alloca \[448 x i8\], align 8', line):
                    continue
                if '= getelementptr' in line:
                    require(model.pointer(line.split(' =')[0]) is not None, 'inlined checkpoint hidden pointer alias')
                    continue
                require((label, index) in visited, 'inlined checkpoint temporary storage escapes checked lifetime')
        visited_all.update(visited)
        records.append((point, exits[0], exits[2]))
    return records, visited_all
