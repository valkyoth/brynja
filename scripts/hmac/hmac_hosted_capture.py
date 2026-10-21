"""Exact launch-record provenance, not whole-host or worker erasure."""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_hosted_lifecycle as lifecycle

require, VALUE = common.require, syntax.VALUE
TYPE = r'(ptr|i8|i64|<2 x i64>)'
WIDTH = {'ptr': 8, 'i8': 1, 'i64': 8, '<2 x i64>': 16}


def pointer(root, offset=0):
    return tuple(('pointer', root, offset, byte) for byte in range(8))


def address(value):
    require(len(value) == 8 and value[0][0] == 'pointer'
            and value == pointer(value[0][1], value[0][2]), 'capture pointer lost provenance')
    return value[0][1:3]


def dominates(graph):
    start = next(iter(graph))
    edges = {label: set(re.findall(r'label %' + common.LABEL, ' '.join(lines)))
             for label, lines in graph.items()}
    require(all(target in graph for targets in edges.values() for target in targets),
            'unknown capture control-flow target')
    reachable, pending = set(), [start]
    while pending:
        label = pending.pop()
        if label not in reachable:
            reachable.add(label)
            pending.extend(edges[label])
    dom = {label: ({start} if label == start else set(reachable)) for label in reachable}
    changed = True
    while changed:
        changed = False
        for label in reachable - {start}:
            parents = [dom[parent] for parent in reachable if label in edges[parent]]
            result = {label} | set.intersection(*parents)
            if dom[label] != result:
                dom[label], changed = result, True
    return dom


class Record:
    def __init__(self, arguments, body, names, target, compiled):
        self.graph = common.blocks(body)
        self.dom = dominates(self.graph)
        self.names, self.target = names, target
        self.defs, self.writes, self.allocs = {}, [], {}
        params = syntax.parameters(arguments)
        require(len(params) == 5, 'host capture parameter count')
        self.self_pointer = syntax.operand(params[0])
        self.request = syntax.operand(params[1])
        self.cancel = syntax.operand(params[4])
        self.formals = {self.self_pointer: pointer('self'), self.request: pointer('request'),
                        self.cancel: pointer('cancel'), syntax.operand(params[2]): pointer('candidate-input')}
        length = re.search('(' + VALUE + ')$', params[3])
        require(length and params[3].startswith('i64 '), 'candidate length argument')
        self.formals[length[1]] = tuple(('candidate-length', byte) for byte in range(8))
        require('dereferenceable(56)' in params[1]
                and f'dereferenceable({272 if compiled else 256})' in params[0],
                'host/request capture layout changed')
        self.create = None
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                point = label, index
                define = re.match('(' + VALUE + ') = (.*)', line)
                if define:
                    require(define[1] not in self.defs, 'duplicate capture SSA')
                    self.defs[define[1]] = define[2], point
                    alloc = re.fullmatch(r'alloca \[(\d+) x i8\], align \d+', define[2])
                    if alloc:
                        self.allocs[define[1]] = int(alloc[1])
                store = re.match('store ' + TYPE + ' (' + VALUE + r'|-?\d+|null), ptr (' + VALUE + '),', line)
                if store:
                    self.writes.append(('store', point, store[3], WIDTH[store[1]], store[2], store[1]))
                call = syntax.call(line)
                if call and call[0] == 'llvm.memcpy.p0.p0.i64':
                    args = call[1]
                    size = re.fullmatch(r'i64 (\d+)', args[2])
                    require(size, 'variable capture copy extent')
                    self.writes.append(('copy', point, syntax.operand(args[0]), int(size[1]),
                                        syntax.operand(args[1]), None))
                if call and call[0] == 'pthread_create':
                    require(self.create is None, 'duplicate capture launch')
                    self.create = point, syntax.operand(call[1][3])
                require(not re.search(r'\b(?:inttoptr|ptrtoint|bitcast|atomicrmw|cmpxchg)\b', line),
                        'unsupported capture alias or atomic write')
                require(not line.startswith('store ') or store, 'unparsed capture store')
        require(self.create, 'missing capture launch')
        self.cache = {}

    def before(self, first, second):
        return (first[0] == second[0] and first[1] < second[1]
                or first[0] != second[0] and first[0] in self.dom.get(second[0], set()))

    def can_precede(self, first, second):
        if first[0] == second[0] and first[1] < second[1]:
            return True
        seen, pending = set(), re.findall(r'label %' + common.LABEL, ' '.join(self.graph[first[0]]))
        while pending:
            label = pending.pop()
            if label == second[0]:
                return True
            if label not in seen:
                seen.add(label)
                pending.extend(re.findall(r'label %' + common.LABEL, ' '.join(self.graph[label])))
        return False

    def value(self, name, kind, use, trail=()):
        require(len(trail) < 80 and name not in trail, 'cyclic capture provenance')
        if name == 'null':
            return pointer('null')
        if re.fullmatch(r'-?\d+', name):
            return tuple(('constant', byte) for byte in int(name).to_bytes(WIDTH[kind], 'little', signed=int(name) < 0))
        if name in self.formals:
            result = self.formals[name]
        elif name in self.allocs:
            require(self.before(self.defs[name][1], use), 'allocation does not dominate capture')
            result = pointer(name)
        else:
            require(name in self.defs, 'unknown capture SSA: ' + name)
            rhs, point = self.defs[name]
            require(self.before(point, use), 'capture SSA does not dominate use')
            key = name, kind
            if key in self.cache:
                return self.cache[key]
            gep = re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? i8, ptr (' + VALUE + r'), i64 (\d+)', rhs)
            load = re.match('load ' + TYPE + ', ptr (' + VALUE + '),', rhs)
            extract = re.match(r'extractvalue \{ ptr, i64 \} (' + VALUE + '), ([01])', rhs)
            if gep:
                root, offset = address(self.value(gep[1], 'ptr', point, (*trail, name)))
                result = pointer(root, offset + int(gep[2]))
            elif load:
                source = address(self.value(load[2], 'ptr', point, (*trail, name)))
                result = self.read(source, WIDTH[load[1]], point, (*trail, name))
            elif extract:
                rhs_call, call_point = self.defs[extract[1]]
                invocation = syntax.call(rhs_call)
                _, resource = lifecycle.profile(self.target)
                require(invocation and self.names.get(invocation[0]) == '<' + resource + '::Mapping>::bytes_mut',
                        'unknown capture slice factory')
                location = address(self.value(syntax.operand(invocation[1][0]), 'ptr', call_point, (*trail, name)))
                require(location in (('self', 136), ('self', 192)), 'slice not from staging/output mapping')
                role = 'staging' if location[1] == 136 else 'destination'
                result = pointer(role) if extract[2] == '0' else tuple((role + '-length', byte) for byte in range(8))
            else:
                require(False, 'unsupported capture value: ' + rhs)
            self.cache[key] = result
        require(len(result) == WIDTH[kind], 'capture scalar width changed')
        return result

    def read(self, location, size, use, trail=()):
        root, offset = location
        if root == 'request':
            require(0 <= offset and offset + size <= 56, 'request descriptor read out of bounds')
            return tuple(('request', byte) for byte in range(offset, offset + size))
        if root == 'self':
            if offset == 0 and size == 16 or offset == 257 and size == 1:
                return tuple(('public-self', byte) for byte in range(offset, offset + size))
            if self.target != 'aarch64-apple-darwin':
                for start, role in ((136, 'staging'), (192, 'destination')):
                    if size == 8 and offset == start:
                        return pointer(role)
                    if size == 8 and offset == start + 40:
                        return tuple((role + '-length', byte) for byte in range(8))
            require(False, 'unreviewed self field in capture')
        require(root in self.allocs and 0 <= offset and offset + size <= self.allocs[root],
                'capture dereferences payload/unowned storage')
        result = [None] * size
        for mode, point, dest, extent, source, kind in self.writes:
            # Only constant GEPs/local addresses can be store destinations here.
            # Reads through an unknown stored pointer fail, never become public.
            target = self.destination(dest)
            if target[0] != root or target[1] >= offset + size or target[1] + extent <= offset:
                continue
            require(self.before(point, use), 'capture write does not dominate use or is later overwritten')
            if mode == 'store':
                value = self.value(source, kind, point, trail)
            else:
                value = self.read(address(self.value(source, 'ptr', point, trail)), extent, point, trail)
            for index in range(max(offset, target[1]), min(offset + size, target[1] + extent)):
                require(result[index - offset] is None, 'overlapping capture initialization')
                result[index - offset] = value[index - target[1]]
        require(all(byte is not None for byte in result), 'incomplete capture initialization')
        return tuple(result)

    def destination(self, name):
        if name in self.allocs:
            return name, 0
        if name == self.self_pointer:
            return 'self', 0
        require(name in self.defs, 'unknown capture write destination')
        rhs, _ = self.defs[name]
        gep = re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? i8, ptr (' + VALUE + r'), i64 (\d+)', rhs)
        require(gep, 'unresolved capture write alias')
        root, offset = self.destination(gep[1])
        return root, offset + int(gep[2])


def check(arguments, body, names, target, compiled):
    record = Record(arguments, body, names, target, compiled)
    launch, job_name = record.create
    job = address(record.value(job_name, 'ptr', launch))
    require(job[1] == 0 and record.allocs[job[0]] == (136 if compiled else 128), 'launch record size changed')
    shift = 8 if compiled else 0
    # Fixed current layouts; meaningful bytes only. Request and Job padding are
    # not secret owners and do not carry an erasure guarantee.
    expected = {72 + shift: pointer('%candidate'), 80 + shift: pointer('cancel'),
                88 + shift: pointer('staging'),
                96 + shift: tuple(('staging-length', byte) for byte in range(8)),
                104 + shift: pointer('destination'),
                112 + shift: tuple(('destination-length', byte) for byte in range(8)),
                120 + shift: (('constant', 0),), 121 + shift: (('constant', 0),)}
    # Local names are not authority: require exact allocation extent and contents.
    for offset, local, size in ((0, '%result', 2), (8 + shift, '%policy', 16)):
        require(record.allocs.get(local) == size, 'captured local owner shape changed')
        expected[offset] = pointer(local)
    require(record.read(('%policy', 0), 16, launch) == tuple(('public-self', byte) for byte in range(16)),
            'captured policy is not public session metadata')
    require(record.allocs.get('%candidate') == 16, 'candidate descriptor extent')
    require(record.read(('%candidate', 0), 16, launch) == pointer('candidate-input')
            + tuple(('candidate-length', byte) for byte in range(8)), 'candidate descriptor provenance')
    if compiled:
        require(record.allocs.get('%kernel') == 1 and record.read(('%kernel', 0), 1, launch)
                == (('public-self', 257),), 'captured kernel is not public session metadata')
        expected[8] = pointer('%kernel')
    expected[16 + shift] = tuple(('request', byte) for byte in range(56))
    meaningful = {offset + byte for offset, value in expected.items() for byte in range(len(value))}
    for _, point, dest, size, _, _ in record.writes:
        root, offset = record.destination(dest)
        if root == job[0]:
            require(record.before(point, launch) and set(range(offset, offset + size)) <= meaningful,
                    'additional/late launch capture write')
    for offset, value in expected.items():
        require(record.read((job[0], offset), len(value), launch) == value,
                'launch capture field provenance changed at ' + str(offset))
    borrowed = {job[0], '%result', '%policy', '%candidate'} | ({'%kernel'} if compiled else set())
    for label, lines in record.graph.items():
        for index, line in enumerate(lines):
            call = syntax.call(line)
            if call and call[0] == 'llvm.lifetime.end.p0':
                require(len(call[1]) in (1, 2), 'unknown lifetime intrinsic signature')
                local = record.destination(syntax.operand(call[1][-1]))[0]
                require(local not in borrowed or not record.can_precede((label, index), launch),
                        'captured local lifetime ended before launch')
    return record
