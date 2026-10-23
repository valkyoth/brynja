"""Actual fixture AND leaf retained-update graphs, not marker-only evidence."""
import re

import legacy_hmac_execution_state as model

require, flow, final = model.require, model.flow, model.final
SSA, VALUE = model.SSA, model.VALUE


class Graph:
    def __init__(self, fixture, leaf, compiler, panic):
        require(compiler in ("1.90.0", "1.99.1") and panic in ("abort", "unwind"), "unknown execution profile")
        self.modules = [flow.definitions_and_aliases(text) for text in (fixture, leaf)]
        require(not any(model.method(name, op) for part in self.modules[0] for name in part
                        for op in ("update", "cancel")), "fixture shadows leaf implementation")
        self.panic = panic
        self.ok = -1 if compiler == "1.99.1" else 8
        self.stream_ok = -1 if compiler == "1.99.1" else 3

    def resolve(self, symbol, module):
        definitions, aliases = self.modules[module]
        if symbol not in definitions and symbol not in aliases:
            require(module == 0 and any(model.method(symbol, op) for op in ("update", "cancel")),
                    "unexpected cross-module call")
            module = 1
            definitions, aliases = self.modules[module]
        arguments, body = flow.resolve(symbol, definitions, aliases)
        return module, arguments, body

    def walk(self, symbol, module, arguments, state, outcome, depth=0, exceptional=False):
        require(depth < 8, "recursive retained graph")
        module, signature, body = self.resolve(symbol, module)
        params = [re.search(rf"({SSA})$", argument)[1] for argument in final.parameters(signature)]
        require(len(params) == len(arguments), "retained signature changed")
        graph = flow.blocks(body)
        queue = [(next(iter(graph)), None, dict(zip(params, arguments)), state.clone(), exceptional)]
        results, steps = [], 0
        while queue:
            label, predecessor, values, current, unwinding = queue.pop()
            require(label in graph, "missing retained edge")
            steps += 1
            require(steps < 1000, "cyclic retained graph")
            lines, terminal = graph[label], False

            def value(text):
                return model.operand(text, values)

            def schedule(target, child=None, exception=unwinding, updated=None):
                queue.append((target, label, dict(values if updated is None else updated),
                              (current if child is None else child).clone(), exception))

            for index, line in enumerate(lines):
                allocation = re.fullmatch(rf"({SSA}) = alloca \[(\d+) x i8\], align \d+", line)
                store = re.match(rf"store i8 ({VALUE}), ptr ({SSA}),", line)
                indirect = re.search(r"\b(call|invoke) void %observer\(\)", line)
                if allocation:
                    require(int(allocation[2]) in (model.SIZE, model.ENGINE), "unexpected retained allocation")
                    root = (module, symbol, depth, allocation[1])
                    require(root not in current.storage, "repeated retained allocation")
                    current.storage[root] = None
                    current.capacity[root] = int(allocation[2])
                    values[allocation[1]] = (root, 0)
                    continue
                if model.scalar(line, values, current, predecessor):
                    continue
                if store:
                    current.store(value(store[2]), value(store[1]))
                    continue
                invocation = None if indirect else final.call(line)
                if invocation or indirect:
                    callee, args = invocation if invocation else ("%observer", [])
                    kind = "invoke" if re.search(r"\binvoke\b", line) else "call"
                    result = re.match(rf"({SSA}) = ", line)
                    if callee.startswith("llvm.lifetime."):
                        pointer = value(final.operand(args[-1]))
                        if len(args) == 2:
                            require(args[0] in ("i64 904", "i64 912"), "unknown lifetime extent")
                        if callee == "llvm.lifetime.end.p0":
                            current.end(pointer)
                        else:
                            require(callee == "llvm.lifetime.start.p0" and pointer[1] == 0
                                    and pointer[0] in current.storage and current.storage[pointer[0]] is None,
                                    "restarted owner lifetime")
                        continue
                    if callee == "llvm.memcpy.p0.p0.i64":
                        require(len(args) == 4 and args[3] == "i1 false", "unknown owner copy")
                        extent = re.fullmatch(r"i64 (904|912)", args[2])
                        require(extent, "wrong retained copy extent")
                        current.transfer(value(final.operand(args[0])), value(final.operand(args[1])), int(extent[1]))
                        continue
                    if callee in ("llvm.experimental.noalias.scope.decl", "llvm.assume"):
                        # Ignore optimizer assumptions, never use them to prune paths.
                        continue
                    if flow.panic_cleanup(callee):
                        require(unwinding and lines[index + 1:] == ["unreachable"], "unexpected fatal path")
                        terminal = True
                        break
                    if model.shared.owner_drop(callee, "sha1"):
                        require(len(args) == 1 and "dereferenceable(433)" in args[0], "cleanup owner extent")
                        current.destroy(value(final.operand(args[0])))
                        # Separately reviewed primitive destructor is non-panicking.
                        children = [("ret", None, current)]
                    elif model.stream_update(callee):
                        require(len(args) == 3 and result and not current.done and current.updates == 0,
                                "invalid/repeated retained update")
                        pointer = value(final.operand(args[0]))
                        root, offset, metadata, owners = current.region(pointer, 448)
                        require(offset == 8 and metadata[model.NICHE] != 2 and owners == model.OWNERS
                                and "dereferenceable(448)" in args[0]
                                and value(final.operand(args[1])) == ("input", 0)
                                and re.search(r"%input\.1$", args[2]) and value("%input.1") == "input-length",
                                "update not bound to inner owner and caller input")
                        require(kind == "invoke" or self.panic == "abort", "missing update unwind edge")
                        current.updates += 1
                        children = [("resume", None, current)] if outcome == "unwind" else [("ret", outcome, current)]
                    elif callee == "%observer":
                        require(value("%observer") == "observer" and current.updates == 1 and not current.done,
                                "observer not after live successful update")
                        require(kind == "invoke" or self.panic == "abort", "missing observer unwind edge")
                        current.observers += 1
                        children = [("ret", None, current)]
                        if self.panic == "unwind":
                            children.append(("resume", None, current))
                    else:
                        require(model.helper(callee) or any(model.method(callee, op) for op in ("update", "cancel")),
                                "unknown retained callee: " + callee)
                        actual = []
                        for arg in args:
                            match = re.search(rf"({VALUE})$", arg)
                            require(match, "unknown retained call argument")
                            actual.append(value(match[1]))
                        children = self.walk(callee, module, actual, current, outcome, depth + 1, unwinding)
                    if kind == "invoke":
                        edges = re.fullmatch("to label %" + flow.LABEL + " unwind label %" + flow.LABEL
                                             + r"(?:, ![-\w.]+ !\d+)*", lines[index + 1])
                        require(edges, "unknown retained invoke edges")
                        for status, returned, child in children:
                            updated = dict(values)
                            if result and status == "ret":
                                updated[result[1]] = returned
                            schedule(edges[1 if status == "ret" else 2], child, unwinding or status == "resume", updated)
                        terminal = True
                        break
                    normal = [(returned, child) for status, returned, child in children if status == "ret"]
                    if self.panic == "unwind":
                        results.extend((status, returned, child) for status, returned, child in children if status == "resume")
                    if not normal:
                        require(self.panic == "unwind" and children, "call has no continuation")
                        terminal = True
                        break
                    require(len(normal) == 1, "ambiguous normal retained call")
                    returned, current = normal[0]
                    if result:
                        values[result[1]] = returned
                elif line.startswith("br "):
                    direct = re.fullmatch("br label %" + flow.LABEL, line)
                    branch = re.fullmatch(rf"br i1 ({SSA}), label %" + flow.LABEL + ", label %" + flow.LABEL, line)
                    require(direct or branch, "unknown retained branch")
                    if branch:
                        condition = value(branch[1])
                        require(condition in (0, 1), "unknown retained condition")
                    schedule(direct[1] if direct else branch[2 if condition else 3])
                    terminal = True
                    break
                elif line.startswith(("ret ", "resume ")):
                    returned = re.fullmatch(rf"ret i8 ({VALUE})", line)
                    require(returned or line == "ret void" or line.startswith("resume { ptr, i32 }"), "unknown retained return")
                    results.append(("resume" if line.startswith("resume") else "ret",
                                    value(returned[1]) if returned else None, current))
                    terminal = True
                    break
                elif line not in ("cleanup", "filter [0 x ptr] zeroinitializer"):
                    require(False, "unsupported retained instruction: " + line)
            require(terminal, "unterminated retained block")
        require(results, "vacuous retained graph")
        return results

    def consumer(self, operation):
        definitions, aliases = self.modules[0]
        suffix = "36brynja_legacy_hmac_execution_cleanup" + str(len(operation)) + operation
        names = [name for name in (*definitions, *aliases) if re.search(suffix + r"(?:17h\w+E)?$", name)]
        require(len(names) == 1, "missing/ambiguous accelerated consumer: " + operation)
        return names[0]

    def abi(self):
        expected = {"hmac_ok": "i8 " + str(self.ok), "hmac_length": "i8 0", "hmac_fatal": "i8 4",
                    "owner_size": "i64 912", "stream_length": "{ i8, i8 } { i8 1, i8 0 }"}
        for operation, result in expected.items():
            _, arguments, body = self.resolve(self.consumer(operation), 0)
            require(not arguments and body.strip() == "start:\n  ret " + result, "Result/owner ABI probe changed")
        _, arguments, body = self.resolve(self.consumer("stream_ok"), 0)
        require(not arguments and re.fullmatch(r"start:\n  ret \{ i8, i8 \} \{ i8 "
                + str(self.stream_ok) + r", i8 (?:undef|poison) \}", body.strip()), "stream success ABI changed")

    def check(self):
        self.abi()
        for operation in ("cancel", "update", "update_cancel"):
            symbol = self.consumer(operation)
            # Exhaust all byte payloads for Backend/Hash/State, including a
            # conservative superset of inhabited error payloads and all unused
            # success payload values. Independent fixture probes bind the ABI.
            outcomes = [(kind, value) for kind in (self.stream_ok, 0, 1, 2) for value in range(-128, 128)]
            if self.panic == "unwind":
                outcomes += ["unwind"]
            for niche in (0, 1, 2):
                for outcome in outcomes if operation != "cancel" and niche != 2 else [(self.stream_ok, 0)]:
                    state = model.State(niche)
                    arguments = [("state", 0)]
                    if operation != "cancel":
                        arguments += [("input", 0), "input-length"]
                    if operation == "update_cancel":
                        arguments += ["observer"]
                    for status, returned, child in self.walk(symbol, 0, arguments, state, outcome):
                        success = isinstance(outcome, tuple) and outcome[0] == self.stream_ok
                        preserve = (success or outcome == (1, 0)) and niche != 2
                        expected = {0, 1} if niche != 2 and (operation != "update" or not preserve or status == "resume") else set()
                        require(child.done == expected, "retained owner lost/incorrectly destroyed")
                        require(child.updates == int(operation != "cancel" and niche != 2), "vacuous/repeated update")
                        observer = operation == "update_cancel" and niche != 2 and success
                        require(child.observers == int(observer), "missing/spurious successful-update observer")
                        if operation == "update" and niche != 2 and not preserve:
                            require(child.storage["state"][1][model.NICHE] == 2, "fatal update retains engine")
                        if operation == "update" and preserve and status == "ret":
                            require(child.storage["state"][1][model.NICHE] == niche, "ordinary update loses retained engine")
                        if status == "ret" and operation != "cancel":
                            expected_result = self.ok if niche != 2 and success else 0 if niche != 2 and outcome == (1, 0) else 4
                            require(returned == expected_result, "wrong retained update result")
