"""Native launch storage and attribute-result transport, not Job payload proof.

Reviewed resource constructors configure the selected stack and return a Rust
Result. This projection binds its success branch, attribute bytes/pointer and
live local handle/Job storage to the actual pthread_create call. Captured secret
input descriptors and worker output transactions remain separate obligations.
"""
import re

import legacy_hmac_md5_phases as phases
import legacy_hmac_md5_normalization_return as paths

flow, syntax, require, V = phases.flow, phases.syntax, phases.require, phases.VALUE


class Launch:
    def __init__(self, signature, body, names, target, identity, resource):
        self.body, self.graph = body, flow.blocks(body)
        self.allocs = phases.allocations(body)
        self.owner = syntax.operand(syntax.parameters(signature)[0])
        self.ptrs = syntax.pointers(body, (*self.allocs, self.owner))
        self.calls = {(label, index): call for label, lines in self.graph.items()
                      for index, line in enumerate(lines) if (call := syntax.call(line))}
        attributes = [(site, args) for site, (symbol, args) in self.calls.items()
                      if names.get(symbol) == '<' + resource + '::thread::Attributes>::new']
        created = [(site, args) for site, (symbol, args) in self.calls.items() if symbol == 'pthread_create']
        require(len(attributes) == len(created) == 1, 'ambiguous launch binding')
        self.construct, args = attributes[0]
        self.create, native = created[0]
        require(len(args) == 2 and len(native) == 4, 'launch binding arity changed')
        self.result = syntax.operand(args[0])
        self.stack = syntax.operand(args[1])
        require(self.ptrs.get(self.stack) == (self.owner, 72), 'attribute stack is not reviewed session stack field')
        phases.dominates(self.graph, self.construct, self.create)
        self.handle, self.attribute, self.job = (syntax.operand(native[index]) for index in (0, 1, 3))
        expected_job = 96 if identity == 'md5_compiled' else 136 if identity == 'sha1_compiled' else 128
        require(self.allocs.get(self.handle) == 8 and self.allocs.get(self.job) == expected_job,
                'launch handle/Job is not the exact local allocation')
        self.live(self.handle, self.create)
        self.live(self.job, self.create)
        self.live(self.result, self.construct)
        self.chain = []
        self.tracked = {self.result}
        if target == 'aarch64-apple-darwin':
            require(self.allocs.get(self.result) == 16, 'Darwin attribute Result layout changed')
            loads = [(label, index, match) for label, lines in self.graph.items() for index, line in enumerate(lines)
                     if (match := re.fullmatch(re.escape(self.attribute) + rf' = load ptr, ptr ({V}), align 8(?:, !.*)?', line))]
            require(len(loads) == 1 and self.ptrs.get(loads[0][2][1]) == (self.result, 8),
                    'Darwin native attributes not loaded from constructor success')
            self.live(self.result, loads[0][:2])
            phases.dominates(self.graph, loads[0][:2], self.create)
        else:
            width = 56 if target.startswith('x86_64') else 64
            require(self.allocs.get(self.result) == width + 8 and self.allocs.get(self.attribute) == width,
                    'native attribute/Result geometry changed')
            self.transport((self.attribute, 0), width, self.create)
            self.live(self.attribute, self.create)
        self.admission()
        self.no_overwrite(names, resource)

    def live(self, root, use):
        starts, ends = [], []
        require(root in self.allocs, 'launch storage is nonlocal')
        for site, (symbol, args) in self.calls.items():
            if symbol in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0') and syntax.operand(args[-1]) == root:
                require(len(args) in (1, 2) and (len(args) == 1 or args[0] == 'i64 ' + str(self.allocs[root])),
                        'launch storage lifetime extent changed')
                (starts if 'start' in symbol else ends).append(site)
        require(len(starts) == 1, 'launch storage lifetime missing/repeated')
        phases.dominates(self.graph, starts[0], use)
        require(all(not (paths.path(self.graph, starts[0], end) and paths.path(self.graph, end, use)) for end in ends),
                'expired storage at native launch/attribute transfer')

    def transport(self, cursor, width, use):
        if cursor == (self.result, 8):
            self.live(self.result, use)
            phases.dominates(self.graph, self.construct, use)
            return
        require(cursor[0] in self.allocs and cursor[0] not in self.tracked
                and 0 <= cursor[1] <= self.allocs[cursor[0]] - width, 'invalid/cyclic attribute transfer')
        self.tracked.add(cursor[0])
        candidates = []
        for site, (symbol, args) in self.calls.items():
            if symbol != 'llvm.memcpy.p0.p0.i64':
                continue
            dest = self.ptrs.get(syntax.operand(args[0]))
            extent = re.fullmatch(r'i64 (\d+)', args[2])
            if dest and dest[0] == cursor[0]:
                require(extent and args[3] == 'i1 false', 'attribute transfer extent/effect changed')
                size = int(extent[1])
                if dest[1] <= cursor[1] and cursor[1] + width <= dest[1] + size:
                    candidates.append((site, dest, self.ptrs.get(syntax.operand(args[1])), size))
        require(len(candidates) == 1, 'missing/ambiguous complete attribute transfer')
        site, dest, source, size = candidates[0]
        require(source and source[0] in self.allocs and 0 <= source[1] <= self.allocs[source[0]] - size
                and 0 <= dest[1] <= self.allocs[dest[0]] - size, 'attribute copy out of bounds')
        phases.dominates(self.graph, site, use)
        self.live(dest[0], site)
        self.live(source[0], site)
        self.chain.append(site)
        self.transport((source[0], source[1] + cursor[1] - dest[1]), width, site)

    def admission(self):
        loads = [(label, index, match[1]) for label, lines in self.graph.items() for index, line in enumerate(lines)
                 if (match := re.fullmatch(rf'({V}) = load i8, ptr {re.escape(self.result)}, align 8(?:, !.*)?', line))]
        require(len(loads) == 1, 'attribute discriminant missing/repeated')
        label, index, byte = loads[0]
        phases.dominates(self.graph, self.construct, (label, index))
        tail = self.graph[label][index + 1:]
        narrow = re.fullmatch(rf'({V}) = trunc(?: nuw)? i8 {re.escape(byte)} to i1', tail[0]) if tail else None
        branch = re.fullmatch('br i1 ' + re.escape(narrow[1]) + ', label %' + flow.LABEL + ', label %' + flow.LABEL,
                              tail[-1]) if narrow else None
        require(branch, 'native launch lacks attribute-result admission')
        require(self.create[0] not in phases.handoff.reachable(self.graph, branch[1]),
                'attribute constructor failure reaches native launch')
        phases.dominates(self.graph, (branch[2], -1), self.create)

    def no_overwrite(self, names, resource):
        aliases = {name for name, (root, _) in self.ptrs.items() if root in self.tracked}
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                site = label, index
                used = set(re.findall(V, line)) & aliases
                if used and not syntax.call(line):
                    # Only constant-address projections and reads can mention
                    # attribute storage outside the enumerated native calls.
                    allocation = re.fullmatch(rf'{V} = alloca \[\d+ x i8\], align \d+', line)
                    gep = re.fullmatch(rf'({V}) = getelementptr(?: inbounds)?(?: nuw)? i8, ptr {V}, i64 \d+', line)
                    load = re.fullmatch(rf'{V} = load (i8|i16|i64|ptr), ptr ({V}), align \d+(?:, !.*)?', line)
                    if gep:
                        root, offset = self.ptrs.get(gep[1], (None, -1))
                        require(root in self.allocs and 0 <= offset < self.allocs[root], 'attribute alias leaves storage')
                    if load:
                        root, offset = self.ptrs.get(load[2], (None, -1))
                        size = {'i8': 1, 'i16': 2, 'i64': 8, 'ptr': 8}[load[1]]
                        require(root in self.allocs and 0 <= offset <= self.allocs[root] - size,
                                'attribute read leaves storage')
                    require(allocation or gep or load,
                            'attribute pointer escape or unsupported storage use')
                store = re.match(rf'store .+?, ptr ({V}),', line)
                if store:
                    require(self.ptrs.get(store[1], (None,))[0] not in self.tracked,
                            'attribute storage overwritten outside constructor/copy')
                call = syntax.call(line)
                if not call:
                    continue
                symbol, args = call
                name = names.get(symbol, symbol)
                if symbol == 'llvm.memcpy.p0.p0.i64' and self.ptrs.get(syntax.operand(args[0]), (None,))[0] in self.tracked:
                    require(site in self.chain, 'unbound write to attribute storage')
                if ('::thread::Attributes' in name and name.endswith('::drop')) or name in ('__rustc::__rust_dealloc', '__rust_dealloc'):
                    require(not paths.path(self.graph, site, self.create), 'attributes freed before native launch')
                # Existing lifecycle validation rejects unknown callees. No
                # attribute reborrow may smuggle a write through an allowed one.
                touched = any(arg.startswith('ptr ') and re.search(V + '$', arg)
                              and self.ptrs.get(syntax.operand(arg), (None,))[0] in self.tracked for arg in args)
                if touched:
                    require(site == self.construct or site == self.create or site in self.chain
                            or symbol.startswith('llvm.lifetime.') or ('::thread::Attributes' in name and name.endswith('::drop')),
                            'attribute storage escaped to another callee')
