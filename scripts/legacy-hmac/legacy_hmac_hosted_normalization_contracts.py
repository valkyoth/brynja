"""Independent typed Result/initial-owner probes from the downstream fixture."""
import re

import legacy_hmac_hosted_keyed as keyed

syntax, flow, require, V = keyed.syntax, keyed.flow, keyed.require, keyed.V


def literal(kind, value):
    scalar = re.fullmatch(r'i(\d+)', kind)
    vector = re.fullmatch(r'<(\d+) x i(\d+)>', kind)
    require(scalar or vector, 'normalization initializer type changed')
    bits = int(scalar[1] if scalar else vector[2])
    count = 1 if scalar else int(vector[1])
    require(bits % 8 == 0, 'fractional initializer storage')
    values = [value] if scalar else re.findall(r'i\d+ (-?\d+)', value)
    if value == 'zeroinitializer':
        values = ['0'] * count
    require(len(values) == count and all(re.fullmatch(r'-?\d+', item) for item in values),
            'nonliteral normalization initializer')
    return b''.join((int(item) % (1 << bits)).to_bytes(bits // 8, 'little') for item in values)


def initial(body, width):
    graph = flow.blocks(body)
    require(len(graph) == 1, 'conditional normalization initial-owner probe')
    allocs = dict((name, int(size)) for name, size in re.findall(
        '(' + V + r') = alloca \[(\d+) x i8\], align \d+', body))
    memory = {name: [None] * size for name, size in {**allocs, '%_0': width}.items()}
    pointers = syntax.pointers(body, tuple(memory))
    for line in next(iter(graph.values())):
        call = syntax.call(line)
        if call and call[0].startswith('llvm.lifetime.'):
            continue
        if call and call[0] in ('llvm.memset.p0.i64', 'llvm.memcpy.p0.p0.i64'):
            symbol, args = call
            require(args[3] == 'i1 false', 'volatile initial-owner probe changed')
            size = int(args[2].split()[-1])
            if symbol == 'llvm.memset.p0.i64':
                data = list(literal('i8', args[1].split()[-1])) * size
            else:
                root, offset = pointers[syntax.operand(args[1])]
                data = memory[root][offset:offset + size]
            destination = syntax.operand(args[0])
        elif (store := re.match(r'store (i\d+|<\d+ x i\d+>) (.*), ptr (' + V + '), align', line)):
            data, destination = list(literal(store[1], store[2])), store[3]
            size = len(data)
        else:
            require(line == 'ret void' or re.fullmatch('(' + V + r') = (?:alloca|getelementptr) .*', line),
                    'unknown initial-owner probe effect')
            continue
        root, offset = pointers[destination]
        require(0 <= offset <= len(memory[root]) - size and len(data) == size and None not in data,
                'initial-owner probe reads uninitialized/out-of-bounds bytes')
        require(all(value is None for value in memory[root][offset:offset + size]), 'overlapping initial-owner probe')
        memory[root][offset:offset + size] = data
    require(None not in memory['%_0'], 'incomplete initial-owner probe')
    return bytes(memory['%_0'])


def result(signature, body, accepted):
    require('sret([24 x i8])' in signature, 'normalization Result geometry changed')
    graph = flow.blocks(body)
    require(len(graph) == 1, 'conditional normalization Result probe')
    pointers, stores = syntax.pointers(body, ('%_0',)), {}
    for line in next(iter(graph.values())):
        store = re.fullmatch(r'store (ptr|i8|i64) (' + V + r'|-?\d+), ptr (' + V + r'), align \d+', line)
        if store:
            require(store[3] in pointers, 'normalization Result probe writes unknown storage')
            root, offset = pointers[store[3]]
            require(root == '%_0' and offset not in stores, 'overlapping normalization Result probe')
            stores[offset] = (store[1], store[2])
        else:
            require(line == 'ret void' or re.fullmatch(V + r' = getelementptr(?: inbounds)?(?: nuw)? i8, ptr %_0, i64 \d+', line),
                    'unknown normalization Result probe effect')
    expected = ({0: ('i8', '0'), 8: ('ptr', '%owner.0'), 16: ('i64', '%owner.1')} if accepted
                else {0: ('i8', '1'), 1: ('i8', '1')})
    require(stores == expected, 'normalization Result probe fields/discriminant changed')


def validate(population):
    definitions, aliases, names = population
    initials = {}
    for identity, width in (('sha1', 433), ('md5', 113)):
        for operation in ('initial', 'accepted', 'rejected'):
            name = 'brynja_legacy_hmac_hosted_cleanup::normalization::' + identity + '::' + operation
            symbols = [symbol for symbol in (*definitions, *aliases) if names.get(symbol) == name]
            require(len(symbols) == 1, 'missing/ambiguous normalization ABI probe: ' + name)
            signature, body = flow.resolve(symbols[0], definitions, aliases)
            if operation == 'initial':
                require('sret([' + str(width) + ' x i8])' in signature, 'initial-owner probe geometry changed')
                initials[identity] = initial(body, width)
            else:
                result(signature, body, operation == 'accepted')
    return initials
