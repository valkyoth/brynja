"""Legacy batch loan SSA walker: dynamic byte offsets and bounded scalar math.

Kept separate from modern HMAC qualification. Unknown operations fail closed;
callbacks bind actual fields, copied owners, API calls and output writes.
"""
import re
from functools import lru_cache

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_hosted_transaction_values as expressions

V, L, T, require = syntax.VALUE, common.LABEL, expressions.TOKEN, common.require
blocks = lru_cache(maxsize=8)(common.blocks)


def run(body, initial, memory, call, store=None, load=None):
    values, visited = dict(initial), set()
    graph = blocks(body)
    block, predecessor = next(iter(graph)), None

    def value(token):
        if token in ('undef', 'poison'):
            return expressions.Unknown()
        if token in ('null', 'true', 'false'):
            return {'null': None, 'true': 1, 'false': 0}[token]
        if re.fullmatch(r'-?\d+', token):
            return int(token)
        require(token in values, 'unknown loan SSA: ' + token)
        return values[token]

    def argument(arg):
        match = re.search('(' + T + ')$', arg)
        require(match, 'unparsed loan argument')
        return value(match[1])

    while True:
        require(block in graph and block not in visited and len(visited) < 80,
                'cyclic/unknown loan graph')
        visited.add(block)
        lines = graph[block]
        for index, original in enumerate(lines):
            line = original.split(', !', 1)[0]
            assignment = re.match('(' + V + ') = (.*)', line)
            name, rhs = assignment.groups() if assignment else (None, line)
            gep = re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? i8, ptr (' + V + r'), i64 (' + T + ')', rhs)
            read = re.fullmatch(r'load (ptr|i8|i32|i64), ptr (' + V + r'), align \d+', rhs)
            write = re.fullmatch(r'store (ptr|i8|i16|i64) (' + T + r'), ptr (' + V + r'), align \d+', rhs)
            phi = re.fullmatch(r'phi ptr (.*)', rhs)
            insert = re.fullmatch(r'insertvalue (\{ (?:ptr, i64|i8, i8) \}) (' + T
                                  + r'), (ptr|i8|i64) (' + T + '), ([01])', rhs)
            extract = re.fullmatch(r'extractvalue \{ (?:ptr, i64|i8, i8|i64, i1) \} (' + V + '), ([01])', rhs)
            invocation = syntax.call(line)
            if gep:
                base = value(gep[1])
                require(isinstance(base, tuple) and len(base) == 2 and isinstance(base[0], str),
                        'loan pointer provenance lost')
                offset = expressions.integer(value(gep[2]), 64)
                require(0 <= base[1] + offset < 2**63, 'negative/overflowed batch loan pointer offset')
                values[name] = base[0], base[1] + offset
            elif read:
                address = value(read[2])
                require(address in memory, 'loan reads outside reviewed fields')
                if load:
                    load(address, read[1])
                values[name] = memory[address]
            elif write:
                require(store is not None, 'unexpected loan/resource write')
                store(value(write[3]), write[1], value(write[2]))
            elif phi:
                choices = re.findall(r'\[ (' + T + '), %' + L + r' \]', phi[1])
                require(phi[1] == ', '.join('[ ' + v + ', %' + label + ' ]' for v, label in choices),
                        'unparsed loan pointer phi')
                selected = [v for v, label in choices if label == predecessor]
                require(len(selected) == 1, 'unknown loan phi predecessor')
                values[name] = value(selected[0])
            elif insert:
                require(insert[3] == (('ptr', 'i64') if insert[1] == '{ ptr, i64 }' else ('i8', 'i8'))[int(insert[5])],
                        'loan aggregate field type changed')
                previous = value(insert[2])
                require(isinstance(previous, expressions.Unknown) or isinstance(previous, tuple) and len(previous) == 2,
                        'loan aggregate shape')
                result = [expressions.Unknown(), expressions.Unknown()] if isinstance(previous, expressions.Unknown) else list(previous)
                result[int(insert[5])] = value(insert[4])
                values[name] = tuple(result)
            elif extract:
                result = value(extract[1])
                require(isinstance(result, tuple) and len(result) == 2, 'loan extraction shape')
                values[name] = result[int(extract[2])]
            elif invocation:
                symbol, args = invocation
                if symbol == 'llvm.uadd.with.overflow.i64':
                    require(name and 'invoke ' not in line and len(args) == 2
                            and all(arg.startswith('i64 ') for arg in args), 'malformed batch checked addition')
                    total = sum(expressions.integer(argument(arg), 64) for arg in args)
                    values[name] = total % (2**64), int(total >= 2**64)
                    continue
                if symbol == 'llvm.experimental.noalias.scope.decl':
                    require(name is None and 'invoke ' not in line, 'malformed loan noalias declaration')
                    continue
                outcome, result = call(symbol, args, argument)
                if outcome == 'abort':
                    require(index + 1 < len(lines) and lines[index + 1] == 'unreachable',
                            'loan fatal call returns')
                    return 'abort', None, visited
                require(outcome in ('return', 'unwind'), 'unknown loan call outcome')
                if name:
                    values[name] = result
                if 'invoke ' in line:
                    edge = re.match('to label %' + L + ' unwind label %' + L, lines[index + 1])
                    require(edge, 'loan invoke edges missing')
                    predecessor, block = block, edge[1 if outcome == 'return' else 2]
                    break
                require(outcome == 'return', 'loan unwind lacks cleanup edge')
            elif rhs.startswith('br '):
                branch = re.fullmatch('br i1 (' + T + '), label %' + L + ', label %' + L, rhs)
                jump = re.fullmatch('br label %' + L, rhs)
                require(branch or jump, 'unparsed loan branch')
                following = jump[1] if jump else branch[2 if expressions.integer(value(branch[1]), 1) else 3]
                predecessor, block = block, following
                break
            elif rhs.startswith('ret '):
                if rhs == 'ret void':
                    return 'return', None, visited
                returned = re.fullmatch(r'ret (?:i8|i16|i64|\{ ptr, i64 \}|\{ i8, i8 \}) (' + T + ')', rhs)
                require(returned, 'unparsed loan return')
                return 'return', value(returned[1]), visited
            elif rhs.startswith('resume '):
                return 'unwind', None, visited
            elif rhs == 'landingpad { ptr, i32 }':
                require(name, 'unnamed loan landingpad')
                values[name] = expressions.Unknown()
            elif rhs == 'cleanup':
                require(index > 0 and 'landingpad ' in lines[index - 1], 'orphan loan cleanup')
            elif shift := re.fullmatch(r'lshr(?: exact)? i(\d+) (' + T + r'), (\d+)', rhs):
                width, amount = int(shift[1]), int(shift[3])
                require(0 <= amount < width, 'oversized loan shift')
                number, known = expressions.parts(value(shift[2]))
                require(type(number) is int, 'noninteger loan shift')
                mask = (1 << width) - 1
                number, known = (number & mask) >> amount, ((known & mask) >> amount) | ~(mask >> amount)
                values[name] = number if known & mask == mask else expressions.Unknown(number, known)
            elif add := re.fullmatch(r'add(?: nuw| nsw)* i(\d+) (' + T + '), (' + T + ')', rhs):
                width = int(add[1])
                total = expressions.integer(value(add[2]), width) + expressions.integer(value(add[3]), width)
                require(' nuw ' not in rhs or total < 2**width, 'batch unsigned addition produced poison')
                require(' nsw ' not in rhs, 'unreviewed signed batch addition')
                values[name] = total & ((1 << width) - 1)
            elif compare := re.fullmatch(r'icmp ugt i(\d+) (' + T + '), (' + T + ')', rhs):
                values[name] = int(expressions.integer(value(compare[2]), int(compare[1])) > expressions.integer(value(compare[3]), int(compare[1])))
            elif select := re.fullmatch('select i1 (' + T + '), ptr (' + T + '), ptr (' + T + ')', rhs):
                values[name] = value(select[2] if expressions.integer(value(select[1]), 1) else select[3])
            else:
                require(name is not None, 'unreviewed loan instruction: ' + rhs)
                try:
                    values[name] = expressions.evaluate(rhs, value, predecessor)
                except TypeError:
                    require(False, 'noninteger loan expression')
        else:
            require(False, 'unterminated loan graph')
