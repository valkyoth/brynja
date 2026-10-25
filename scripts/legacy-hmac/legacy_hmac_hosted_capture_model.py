"""Byte provenance for legacy launch metadata; never classify key bytes public."""
import re

import legacy_hmac_engine_codegen as shared

base = shared.load('hmac_hosted_capture')
flow, syntax, require = base.common, base.syntax, base.require
V, pointer, address = base.VALUE, base.pointer, base.address
TYPE = r'(ptr|i8|i16|i32|i64|i128|<2 x i64>)'
WIDTH = {**base.WIDTH, 'i16': 2, 'i32': 4, 'i128': 16}


class Record(base.Record):
    def __init__(self, arguments, body, names, target, identity):
        self.signature, self.body = arguments, body
        self.graph = flow.blocks(body)
        self.dom = base.dominates(self.graph)
        self.names, self.target, self.identity = names, target, identity
        self.defs, self.writes, self.allocs, self.cache = {}, [], {}, {}
        batch = identity == 'md5_compiled'
        params = syntax.parameters(arguments)
        require(len(params) == (4 if batch else 5), 'legacy capture parameter count')
        self.self_pointer, self.request = (syntax.operand(arg) for arg in params[:2])
        self.cancel = syntax.operand(params[-1])
        self.formals = {self.self_pointer: pointer('self'), self.request: pointer('inputs' if batch else 'request'),
                        self.cancel: pointer('cancel'), syntax.operand(params[2]): pointer('candidate-input')}
        if not batch:
            require(params[3].startswith('i64 '), 'legacy candidate length type')
            self.formals[params[3].split()[-1]] = tuple(('candidate-length', b) for b in range(8))
        require(f'dereferenceable({320 if batch else 56})' in params[1]
                and f'dereferenceable({256 if identity.endswith("compiled") else 240})' in params[0],
                'legacy host/input capture layout changed')
        self.create = None
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                point = label, index
                define = re.match('(' + V + ') = (.*)', line)
                if define:
                    require(define[1] not in self.defs, 'duplicate capture SSA')
                    self.defs[define[1]] = define[2], point
                    alloc = re.fullmatch(r'alloca \[(\d+) x i8\], align \d+', define[2])
                    if alloc:
                        self.allocs[define[1]] = int(alloc[1])
                store = re.match('store ' + TYPE + ' (' + V + r'|-?\d+|null), ptr (' + V + '),', line)
                if store:
                    self.writes.append(('store', point, store[3], WIDTH[store[1]], store[2], store[1]))
                call = syntax.call(line)
                if call and call[0] == 'llvm.memcpy.p0.p0.i64':
                    args = call[1]
                    size = re.fullmatch(r'i64 (\d+)', args[2])
                    require(size and len(args) == 4 and args[3] == 'i1 false', 'legacy capture copy extent/effect')
                    self.writes.append(('copy', point, syntax.operand(args[0]), int(size[1]),
                                        syntax.operand(args[1]), None))
                if call and call[0] == 'pthread_create':
                    require(self.create is None, 'duplicate legacy capture launch')
                    self.create = point, syntax.operand(call[1][3])
                require(not re.search(r'\b(?:inttoptr|ptrtoint|bitcast|atomicrmw|cmpxchg)\b', line),
                        'unsupported legacy capture alias/atomic')
                require(not line.startswith('store ') or store, 'unparsed legacy capture store')
        require(self.create, 'missing legacy capture launch')

    def value(self, name, kind, use, trail=()):
        require(len(trail) < 80 and name not in trail, 'cyclic legacy capture provenance')
        require(kind in base.WIDTH, 'unreviewed captured scalar width')
        if name in self.defs:
            rhs, point = self.defs[name]
            extract = re.fullmatch(r'extractvalue \{ ptr, i64 \} (' + V + '), ([01])', rhs)
            if extract:
                require(self.before(point, use), 'mapping slice does not dominate capture')
                call_rhs, call_point = self.defs[extract[1]]
                call = syntax.call(call_rhs)
                expected = '<brynja_crypto_cpu_std::macos_resident::memory::ResidentBytes>::as_bytes_mut'
                require(self.target == 'aarch64-apple-darwin' and call and self.names.get(call[0]) == expected
                        and len(call[1]) == 1 and self.before(call_point, point), 'unreviewed capture slice factory')
                location = address(self.value(syntax.operand(call[1][0]), 'ptr', call_point, (*trail, name)))
                require(location in (('self', 128), ('self', 184)), 'slice not from selected staging/output')
                role = 'staging' if location[1] == 128 else 'destination'
                result = pointer(role) if extract[2] == '0' else tuple((role + '-length', b) for b in range(8))
                require(kind == ('ptr' if extract[2] == '0' else 'i64'), 'capture slice component width')
                return result
        return super().value(name, kind, use, trail)

    def read(self, location, size, use, trail=()):
        root, offset = location
        if root == 'self':
            if (offset, size) in ((64, 8), (48, 8), (240, 1)):
                require(offset != 48 or self.identity == 'md5_compiled', 'unexpected captured budget')
                require(offset != 240 or self.identity.endswith('compiled'), 'unexpected captured backend')
                return tuple(('public-self', b) for b in range(offset, offset + size))
            if self.target != 'aarch64-apple-darwin':
                for start, role in ((128, 'staging'), (184, 'destination')):
                    if size == 8 and offset == start:
                        return pointer(role)
                    if size == 8 and offset == start + 40:
                        return tuple((role + '-length', b) for b in range(8))
            require(False, 'unreviewed legacy session field in capture')
        return super().read(location, size, use, trail)
