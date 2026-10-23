"""Conservative pointer roots for stores during MD5 row cleanup.

New local row storage cannot be named by pre-existing safe Rust parameters.
Unknown local pointer results may name ANY row. This analysis never grants a
callee no-write status; unclassified calls still invalidate every live row.
"""
import re

import legacy_hmac_execution_admission as common

VALUE, syntax = common.VALUE, common.syntax


class Origins:
    def __init__(self, signature, body, rows):
        self.rows = set(rows)
        self.allocations = set(re.findall(rf"({VALUE}) = alloca ", body))
        self.parameters = {syntax.operand(arg) for arg in syntax.parameters(signature) if arg.startswith("ptr ")}
        self.expressions = dict(re.findall(rf"^\s*({VALUE}) = (.*)$", body, re.M))
        self.stores = re.findall(rf"store ptr ({VALUE}), ptr ({VALUE}),", body)
        self.copies = []
        for line in body.splitlines():
            call = syntax.call(line)
            if call and call[0] == "llvm.memcpy.p0.p0.i64":
                source = re.search(VALUE + "$", call[1][1])
                self.copies.append((source[0] if source else "unknown-copy-source", syntax.operand(call[1][0])))

    def roots(self, name, trail=frozenset()):
        if name in self.allocations or name in self.parameters:
            return {name}
        if name in trail:
            return self.rows.copy()
        trail = trail | {name}
        expression = self.expressions.get(name, "")
        gep = re.match(rf"getelementptr.*?, ptr ({VALUE}),", expression)
        load = re.match(rf"load ptr, ptr ({VALUE}),", expression)
        if gep:
            return self.roots(gep[1], trail)
        if load:
            containers = self.roots(load[1], trail)
            # External immutable selection/control/input storage cannot contain
            # references to these subsequently allocated local arrays.
            written = any(self.roots(destination, trail) & containers for _, destination in self.stores + self.copies)
            if containers and containers <= self.parameters and not written:
                return containers
            return self.captured(containers, trail)
        if expression.startswith("phi ptr "):
            sources = re.findall(r"\[ (.*?), %" + common.flow.LABEL + r" \]", expression)
            if sources:
                return set().union(*(self.roots(value, trail) for value, _ in sources))
        if expression.startswith("select "):
            sources = re.findall(rf", ptr ({VALUE})(?:,|$)", expression)
            if len(sources) == 2:
                return set().union(*(self.roots(value, trail) for value in sources))
        return self.rows.copy()

    def captured(self, containers, trail):
        result, found = set(), set()
        for value, destination in self.stores:
            roots = self.roots(destination, trail)
            if roots & containers:
                found |= roots & containers
                result |= self.roots(value, trail)
        # Captured pointer records can be moved as bytes. Follow those moves
        # conservatively; no field-offset claim is made by this root analysis.
        for source, destination in self.copies:
            roots = self.roots(destination, trail)
            if roots & containers:
                found |= roots & containers
                if source in trail:
                    result |= self.rows
                else:
                    result |= self.captured(self.roots(source, trail), trail | {source})
        if containers - found:
            result |= self.rows
        return result

    def disjoint_store(self, line):
        store = re.match(rf"store .+?, ptr ({VALUE}),", line)
        return bool(store and not self.roots(store[1]) & self.rows)
