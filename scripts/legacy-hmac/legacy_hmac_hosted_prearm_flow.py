"""Bounded execution of the emitted public-request admission prefix.

Only descriptor metadata is supplied. Reads of key/message/candidate bytes and
unreviewed effects fail closed. Loop phis read one simultaneous predecessor
snapshot. This is a bounded projection, not a general LLVM interpreter.
"""
import re
from functools import lru_cache

import legacy_hmac_hosted_batch_flow as base

values, require, syntax = base.expressions, base.require, base.syntax
V, T, L = base.V, base.T, base.L
blocks = lru_cache(maxsize=16)(base.common.blocks)


def expression(rhs, value, predecessor):
    lane = re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? %"core::option::Option<(?:strict_execution|macos_resident)::md5_compiled::types::Md5BatchInput<\'_>>", ptr (' + V + '), i64 (' + T + ')', rhs)
    if lane:
        pointer, count = value(lane[1]), values.integer(value(lane[2]), 64)
        require(isinstance(pointer, tuple) and len(pointer) == 2 and isinstance(pointer[0], str)
                and 0 <= pointer[1] + count * 40 < 2**63, 'pre-arm lane-array geometry changed')
        return pointer[0], pointer[1] + count * 40
    slices = re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? \{ ptr, i64 \}, ptr (' + V + '), i64 (' + T + ')', rhs)
    if slices:
        pointer, count = value(slices[1]), values.integer(value(slices[2]), 64)
        require(isinstance(pointer, tuple) and len(pointer) == 2 and isinstance(pointer[0], str)
                and 0 <= pointer[1] + count * 16 < 2**63, 'pre-arm slice-array geometry changed')
        return pointer[0], pointer[1] + count * 16
    compare_unknown = re.fullmatch(r'icmp(?: samesign)? \w+ (?:i\d+|ptr) (' + T + '), (' + T + ')', rhs)
    if compare_unknown and any(isinstance(value(compare_unknown[i]), values.Unknown) for i in (1, 2)):
        # A select may discard an undefined Option payload comparison. It must
        # never become a known branch condition or an accepted result.
        return values.Unknown()
    insert = re.fullmatch(r'insertvalue \{ i8, i8 \} (' + T + '), i8 (' + T + '), ([01])', rhs)
    if insert:
        previous = value(insert[1])
        require(isinstance(previous, values.Unknown) or isinstance(previous, tuple) and len(previous) == 2,
                'pre-arm inserted result shape')
        result = [values.Unknown(), values.Unknown()] if isinstance(previous, values.Unknown) else list(previous)
        result[int(insert[3])] = value(insert[2])
        return tuple(result)
    gep = re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? i8, ptr (' + V + '), i64 (' + T + ')', rhs)
    if gep:
        pointer, offset = value(gep[1]), values.integer(value(gep[2]), 64)
        require(isinstance(pointer, tuple) and len(pointer) == 2 and isinstance(pointer[0], str),
                'pre-arm pointer provenance lost')
        # GEP's i64 index is signed. Descriptor paths may retreat after a loop.
        offset = offset if offset < 2**63 else offset - 2**64
        require(0 <= pointer[1] + offset < 2**63, 'pre-arm pointer arithmetic outside address domain')
        return pointer[0], pointer[1] + offset
    binary = re.fullmatch(r'(add|sub|mul)((?: nuw| nsw)*) i(\d+) (' + T + '), (' + T + ')', rhs)
    if binary:
        op, flags, width = binary[1], binary[2], int(binary[3])
        a, b = (values.integer(value(binary[i]), width) for i in (4, 5))
        result = {'add': lambda: a + b, 'sub': lambda: a - b, 'mul': lambda: a * b}[op]()
        if 'nuw' in flags:
            require(0 <= result < 2**width, 'pre-arm unsigned arithmetic produced poison')
        if 'nsw' in flags:
            signed = lambda n: n if n < 2**(width - 1) else n - 2**width
            a, b = signed(a), signed(b)
            result_signed = {'add': lambda: a + b, 'sub': lambda: a - b, 'mul': lambda: a * b}[op]()
            require(-2**(width - 1) <= result_signed < 2**(width - 1), 'pre-arm signed arithmetic produced poison')
        return result % (2**width)
    compare = re.fullmatch(r'icmp(?: samesign)? (ugt|ule|uge) i(\d+) (' + T + '), (' + T + ')', rhs)
    if compare:
        a, b = (values.integer(value(compare[i]), int(compare[2])) for i in (3, 4))
        return int({'ugt': a > b, 'ule': a <= b, 'uge': a >= b}[compare[1]])
    phi = re.fullmatch(r'phi ptr (.*)', rhs)
    if phi:
        return values.evaluate('phi i64 ' + phi[1], value, predecessor)
    nneg = re.fullmatch(r'zext nneg i(\d+) (' + T + r') to i(\d+)', rhs)
    if nneg:
        require(values.integer(value(nneg[2]), int(nneg[1])) < 2**(int(nneg[1]) - 1), 'pre-arm nneg cast produced poison')
        rhs = rhs.replace('zext nneg ', 'zext ', 1)
    shift = re.fullmatch(r'lshr(?: exact)? i(\d+) (' + T + r'), (\d+)', rhs)
    if shift:
        width, amount = int(shift[1]), int(shift[3])
        require(0 <= amount < width, 'pre-arm invalid shift')
        number, known = values.parts(value(shift[2]))
        require(type(number) is int, 'pre-arm noninteger shift')
        mask = 2**width - 1
        return values.Unknown((number & mask) >> amount, ((known & mask) >> amount) | ~(mask >> amount))
    extract = re.fullmatch(r'extractvalue \{ (?:i128, i1|i64, i1|i8, i8) \} (' + V + '), ([01])', rhs)
    if extract:
        result = value(extract[1])
        require(isinstance(result, tuple) and len(result) == 2, 'pre-arm aggregate shape changed')
        return result[int(extract[2])]
    return values.evaluate(rhs, value, predecessor)


def run(body, initial, read, write, call, stop, uses=None):
    graph, env, visited = blocks(body), dict(initial), set()
    block, predecessor = next(iter(graph)), None

    def value(token, source=None):
        source = env if source is None else source
        if token in ('undef', 'poison'):
            return values.Unknown()
        if token in ('null', 'true', 'false'):
            return {'null': None, 'true': 1, 'false': 0}[token]
        if re.fullmatch(r'-?\d+', token):
            return int(token)
        require(token in source, 'pre-arm undefined SSA: ' + token)
        if uses is not None:
            uses.add(token)
        return source[token]

    def argument(arg):
        match = re.search('(' + T + ')$', arg)
        require(match, 'pre-arm operand syntax')
        return value(match[1])

    for _ in range(2048):
        require(block in graph, 'pre-arm unknown block')
        incoming = dict(env)
        for index, original in enumerate(graph[block]):
            line, point = original.split(', !', 1)[0], (block, index)
            visited.add(point)
            if stop(point, line, argument, value):
                return 'admitted', None, visited
            assigned = re.fullmatch('(' + V + ') = (.*)', line)
            name, rhs = assigned.groups() if assigned else (None, line)
            load = re.fullmatch(r'load (ptr|i8|i64|i128), ptr (' + V + r'), align \d+', rhs)
            atomic = re.fullmatch(r'load atomic i8, ptr (' + V + ') acquire, align 1', rhs)
            store = re.fullmatch(r'store (ptr|i8|i16|i64|i128) (' + T + '), ptr (' + V + r'), align \d+', rhs)
            allocation = re.fullmatch(r'alloca \[(\d+) x i8\], align \d+', rhs)
            invocation = syntax.call(line)
            if allocation:
                env[name] = ('local:' + name, 0)
            elif load or atomic:
                env[name] = read(value(atomic[1] if atomic else load[2]), 'atomic' if atomic else load[1])
            elif store:
                write(value(store[3]), store[1], value(store[2]))
            elif invocation:
                symbol, args = invocation
                intrinsic = re.fullmatch(r'llvm.uadd.with.overflow.i(64|128)', symbol)
                if intrinsic:
                    width = int(intrinsic[1])
                    require(name and len(args) == 2 and all(a.startswith('i' + str(width) + ' ') for a in args),
                            'pre-arm checked-add signature')
                    total = sum(values.integer(argument(arg), width) for arg in args)
                    result = total % (2**width), int(total >= 2**width)
                elif symbol == 'llvm.umin.i64':
                    require(name and len(args) == 2 and all(a.startswith('i64 ') for a in args), 'pre-arm minimum signature')
                    result = min(values.integer(argument(arg), 64) for arg in args)
                elif symbol == 'llvm.experimental.noalias.scope.decl':
                    require(name is None and 'invoke ' not in line, 'pre-arm noalias effect changed')
                    continue
                elif symbol.startswith('llvm.lifetime.'):
                    pointer = argument(args[-1])
                    require(symbol in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0')
                            and isinstance(pointer, tuple) and pointer[0].startswith('local:')
                            and pointer[1] == 0, 'pre-arm nonlocal lifetime')
                    call(symbol, args, argument)
                    continue
                else:
                    result = call(symbol, args, argument)
                if name:
                    env[name] = result
                if 'invoke ' in line:
                    edge = re.fullmatch('to label %' + L + ' unwind label %' + L, graph[block][index + 1])
                    require(edge, 'pre-arm invoke edges missing')
                    predecessor, block = block, edge[1]
                    break
            elif rhs.startswith('br '):
                branch = re.fullmatch('br i1 (' + T + '), label %' + L + ', label %' + L, rhs)
                jump = re.fullmatch('br label %' + L, rhs)
                require(branch or jump, 'pre-arm unparsed branch')
                target = jump[1] if jump else branch[2 if values.integer(value(branch[1]), 1) else 3]
                predecessor, block = block, target
                break
            elif rhs.startswith('ret '):
                returned = re.fullmatch(r'ret (?:i16|\{ i8, i8 \}) (' + T + ')', rhs)
                require(returned, 'pre-arm return representation changed')
                return 'rejected', value(returned[1]), visited
            else:
                require(name, 'unreviewed pre-arm instruction: ' + rhs)
                try:
                    env[name] = expression(rhs, lambda token: value(token, incoming) if rhs.startswith('phi ') else value(token), predecessor)
                except (TypeError, IndexError):
                    require(False, 'pre-arm expression type changed')
        else:
            require(False, 'unterminated pre-arm block')
    require(False, 'pre-arm bounded traversal exceeded')
