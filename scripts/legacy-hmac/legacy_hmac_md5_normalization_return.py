"""Bind normalization report copies, storage lifetimes and success admission.

The separately checked pads helper supplies the 24 report bytes. Follow every
copy to the returned report; reject other writes, address escapes and expired
storage. This is conditional field transport, not every-return qualification.
"""
import re

import legacy_hmac_md5_report_return as returned
import legacy_hmac_md5_return_writes as output

n, phases, flow, syntax, require, VALUE = returned.n, returned.phases, returned.flow, returned.syntax, returned.require, returned.VALUE


def path(graph, before, after):
    """Whether a CFG path can run after before and reach after (including loops)."""
    if before[0] == after[0] and before[1] < after[1]:
        return True
    children = re.findall('label %' + flow.LABEL, '\n'.join(graph[before[0]]))
    return any(after[0] in phases.handoff.reachable(graph, child) for child in children)


class Check:
    def __init__(self, body, base):
        self.body, self.graph = body, flow.blocks(body)
        self.allocs = phases.allocations(body)
        self.pointers = syntax.pointers(body, (*self.allocs, '%_0'))
        self.pad = phases.one(body, lambda name, args: phases.identity(name, 'pads'), 'normalization return')
        self.root = syntax.operand(self.pad[3][0])
        require(self.allocs.get(self.root) == 32, 'normalization result extent changed')
        self.copies = []
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                call = syntax.call(line)
                if call and call[0] == 'llvm.memcpy.p0.p0.i64' and all('@' not in arg for arg in call[1][:2]):
                    dest, source = (self.pointers.get(syntax.operand(arg)) for arg in call[1][:2])
                    self.copies.append(((label, index), dest, source, call[1][2:]))
        self.chain, self.roots = [], {self.root: 8}
        dest = ('%_0', base + 8)
        while True:
            candidates = [copy for copy in self.copies if copy[1] == dest]
            require(len(candidates) == 1, 'normalization return copy missing/repeated')
            copy = candidates[0]
            require(copy[3] == ['i64 24', 'i1 false'], 'normalization return copy extent/effect changed')
            self.chain.append(copy)
            source = copy[2]
            if source == (self.root, 8):
                break
            require(source and source[0] in self.allocs and 0 <= source[1] <= self.allocs[source[0]] - 24
                    and source[0] not in self.roots, 'normalization return source is not a distinct report owner')
            self.roots[source[0]] = source[1]; dest = source
        self.chain.reverse()
        writes = [site for site, offset, size, _, _ in output.writes(body)
                  if output.overlap(offset, size, base + 8, 24)]
        require(writes == [self.chain[-1][0]], 'returned normalization report overwritten/overlapped')
        self.starts, self.ends, self.loads = {root: [] for root in self.roots}, {root: [] for root in self.roots}, []
        self.uses()
        self.admission()
        writes = {self.root: self.pad[:2]}
        for site, dest, source, _ in self.chain:
            phases.dominates(self.graph, writes[source[0]], site)
            self.live(source[0], writes[source[0]], site)
            if dest[0] != '%_0':
                self.live(dest[0], site, site)
                writes[dest[0]] = site
        self.live(self.root, self.pad[:2], self.pad[:2])

    def live(self, root, write, read):
        starts = self.starts[root]
        require(len(starts) == 1, 'normalization report lifetime missing/repeated')
        phases.dominates(self.graph, starts[0], write)
        for end in self.ends[root]:
            require(not (path(self.graph, starts[0], end) and path(self.graph, end, read)),
                    'normalization report consumed after lifetime end')

    def uses(self):
        names = {name for name, address in self.pointers.items() if address[0] in self.roots}
        permitted = {copy[0] for copy in self.chain}
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                if not set(re.findall(VALUE, line)) & names:
                    continue
                site, call = (label, index), syntax.call(line)
                if site == self.pad[:2] or site in permitted:
                    continue
                allocation = re.fullmatch(rf'({VALUE}) = alloca \[(\d+) x i8\], align \d+', line)
                gep = re.fullmatch(n.pads.descriptors.GEP, line)
                load = re.fullmatch(rf'({VALUE}) = load i8, ptr ({VALUE}), align [18](?:, !.*)?', line)
                if allocation:
                    require(allocation[1] in self.roots, 'unbound report allocation')
                elif gep:
                    require(gep[1] in names and (self.pointers[gep[1]][1] == self.roots[self.pointers[gep[1]][0]]
                            or self.pointers[gep[1]] == (self.root, 1)), 'unbound report alias')
                elif load:
                    require(self.pointers.get(load[2]) in ((self.root, 0), (self.root, 1)),
                            'normalization report bytes escaped into unbound values')
                    self.loads.append((site, load[1], self.pointers[load[2]][1]))
                    phases.dominates(self.graph, self.pad[:2], site)
                elif call and call[0] in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0'):
                    address = self.pointers.get(syntax.operand(call[1][-1]))
                    require(address and address[1] == 0 and address[0] in self.roots and len(call[1]) in (1, 2)
                            and (len(call[1]) == 1 or call[1][0] == 'i64 ' + str(self.allocs[address[0]])),
                            'normalization lifetime identity changed')
                    (self.starts if 'start' in call[0] else self.ends)[address[0]].append(site)
                else:
                    require(False, 'unreviewed normalization report storage use: ' + line)
        for site, _, _ in self.loads:
            self.live(self.root, self.pad[:2], site)

    def admission(self):
        normal, unwind = n.results.continuation(self.graph, self.pad)
        label, index = normal
        lines = self.graph[label][index:]
        loads = [(site, name) for site, name, offset in self.loads if offset == 0]
        require(len(loads) == 1 and loads[0][0] == normal and len(lines) == 3,
                'normalization return guard shape changed')
        narrow = re.fullmatch(rf'({VALUE}) = trunc(?: nuw)? i8 {re.escape(loads[0][1])} to i1', lines[1])
        branch = re.fullmatch(r'br i1 (%[-\w.]+), label %' + flow.LABEL + ', label %' + flow.LABEL, lines[2])
        require(narrow and branch and branch[1] == narrow[1], 'normalization return success predicate changed')
        for site, _, _, _ in self.chain:
            phases.dominates(self.graph, (branch[3], -1), site)
            require(site[0] not in phases.handoff.reachable(self.graph, branch[2]),
                    'normalization failure reaches returned report')
            if unwind:
                require(site[0] not in phases.handoff.reachable(self.graph, unwind[0]),
                        'normalization unwind reaches returned report')


def validate(fixture, llvm):
    offsets = returned.layout.validate(fixture)
    definitions, aliases = flow.definitions_and_aliases(llvm)
    return [Check(phases.rows.method(definitions, aliases, operation)[1][1], base)
            for operation, base in offsets.items()]
