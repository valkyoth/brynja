"""Complete meaningful launch-record fields, with live borrowed descriptors."""
import re

import legacy_hmac_hosted_capture_model as model

Record, require, syntax = model.Record, model.require, model.syntax
pointer, address, V = model.pointer, model.address, model.V


def check(arguments, body, names, target, identity):
    record = Record(arguments, body, names, target, identity)
    launch, operand = record.create
    job, offset = address(record.value(operand, 'ptr', launch))
    batch, compiled = identity == 'md5_compiled', identity == 'sha1_compiled'
    size = 96 if batch else 136 if compiled else 128
    require(offset == 0 and record.allocs.get(job) == size, 'legacy launch record geometry changed')
    expected, borrowed = {}, {job}

    def borrow(offset, root, size):
        require(record.allocs.get(root) == size, 'legacy captured local geometry changed: ' + root)
        expected[offset] = pointer(root)
        borrowed.add(root)

    def local(root, offset, value):
        require(record.read((root, offset), len(value), launch) == value,
                'legacy captured local provenance changed: ' + root)

    if batch:
        borrow(32, '%result', 2)
        borrow(48, '%candidates', 8)
        local('%candidates', 0, pointer('candidate-input'))
        expected.update({0: pointer('staging'), 8: tuple(('staging-length', b) for b in range(8)),
                         16: pointer('destination'), 24: tuple(('destination-length', b) for b in range(8)),
                         40: pointer('inputs'), 56: pointer('cancel'),
                         64: tuple(('public-self', b) for b in range(64, 72)),
                         72: tuple(('public-self', b) for b in range(48, 56)),
                         80: (('public-self', 240),), 88: (('constant', 0),), 89: (('constant', 0),)})
    else:
        shift = 8 if compiled else 0
        borrow(0, '%result', 2)
        borrow(8 + shift, '%bytes', 8)
        borrow(72 + shift, '%candidate', 16)
        local('%bytes', 0, tuple(('public-self', b) for b in range(64, 72)))
        local('%candidate', 0, pointer('candidate-input') + tuple(('candidate-length', b) for b in range(8)))
        if compiled:
            borrow(8, '%backend', 1)
            local('%backend', 0, (('public-self', 240),))
        expected.update({16 + shift: tuple(('request', b) for b in range(56)), 80 + shift: pointer('cancel'),
                         88 + shift: pointer('staging'), 96 + shift: tuple(('staging-length', b) for b in range(8)),
                         104 + shift: pointer('destination'), 112 + shift: tuple(('destination-length', b) for b in range(8)),
                         120 + shift: (('constant', 0),), 121 + shift: (('constant', 0),)})
    # Result::Err(Invariant) starts with this current discriminant; its second
    # byte is not meaningful until the worker writes a concrete result.
    local('%result', 0, (('constant', 8),))
    meaningful = {offset + b for offset, value in expected.items() for b in range(len(value))}
    for _, point, dest, extent, _, _ in record.writes:
        root, offset = record.destination(dest)
        if root == job:
            require(record.before(point, launch) and set(range(offset, offset + extent)) <= meaningful,
                    'additional/late legacy capture write')
    for offset, value in expected.items():
        require(record.read((job, offset), len(value), launch) == value,
                'legacy launch capture changed at ' + str(offset))
    for root in borrowed:
        require(record.before(record.defs[root][1], launch), 'captured allocation does not dominate launch')
    for label, lines in record.graph.items():
        for index, line in enumerate(lines):
            call = syntax.call(line)
            if call and call[0].startswith('llvm.lifetime.'):
                root, offset = record.destination(syntax.operand(call[1][-1]))
                if root not in borrowed:
                    continue
                require(offset == 0 and len(call[1]) in (1, 2)
                        and (len(call[1]) == 1 or call[1][0] == 'i64 ' + str(record.allocs[root])),
                        'captured local lifetime geometry changed')
                if call[0] == 'llvm.lifetime.end.p0':
                    require(not record.can_precede((label, index), launch), 'captured local expired before launch')
                else:
                    require(call[0] == 'llvm.lifetime.start.p0' and record.before((label, index), launch),
                            'captured local lifetime starts after launch')
    record.borrowed, record.expected, record.job = borrowed, expected, job
    isolation(record)
    return record


def isolation(record):
    """Captured local addresses cannot be smuggled to an otherwise allowed call."""
    ptrs = syntax.pointers('\n'.join('\n'.join(lines) for lines in record.graph.values()), record.allocs)
    aliases = {name for name, (root, _) in ptrs.items() if root in record.borrowed}
    for label, lines in record.graph.items():
        for index, line in enumerate(lines):
            mentioned = set(re.findall(V, line)) & aliases
            if not mentioned:
                continue
            call = syntax.call(line)
            if call:
                symbol, args = call
                if symbol == 'pthread_create':
                    require((label, index) == record.create[0]
                            and [i for i, arg in enumerate(args) if set(re.findall(V, arg)) & aliases] == [3],
                            'captured local escaped through native launch')
                elif symbol == 'llvm.memcpy.p0.p0.i64':
                    require(ptrs.get(syntax.operand(args[0]), (None,))[0] == record.job
                            and not (set(re.findall(V, args[1])) & aliases), 'captured local copied elsewhere')
                else:
                    require(symbol in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0'),
                            'captured local escaped to another callee')
                continue
            if re.fullmatch(V + r' = alloca \[\d+ x i8\], align \d+', line):
                continue
            gep = re.fullmatch(r'(' + V + r') = getelementptr(?: inbounds)?(?: nuw)? i8, ptr ' + V + r', i64 \d+', line)
            if gep:
                root, offset = ptrs.get(gep[1], (None, -1))
                require(root in record.borrowed and 0 <= offset < record.allocs[root], 'capture alias outside allocation')
                continue
            load = re.match(V + ' = load ' + model.TYPE + ', ptr (' + V + '),', line)
            store = re.match('store ' + model.TYPE + ' (' + V + r'|-?\d+|null), ptr (' + V + '),', line)
            if load or store:
                kind, dest = (load[1], load[2]) if load else (store[1], store[3])
                root, offset = ptrs.get(dest, (None, -1))
                require(root in record.borrowed and 0 <= offset <= record.allocs[root] - model.WIDTH[kind],
                        'capture access/escape outside borrowed local')
                if store and store[2] in aliases:
                    require(kind == 'ptr' and root == record.job, 'captured pointer stored outside launch record')
                continue
            require(False, 'unreviewed captured-local alias or use: ' + line)
