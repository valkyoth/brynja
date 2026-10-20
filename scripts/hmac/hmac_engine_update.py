"""Cleanup dispatch after update success, error or observer unwind."""
import re

import hmac_engine_codegen as codegen
from hmac_engine_codegen import LABEL, require


def helper(symbol, identity, definitions, aliases):
    require(("drop_glue" in symbol or "drop_in_place" in symbol)
            and "brynja_mac_hmac" in symbol, "unexpected update cleanup helper")
    arguments, body = codegen.resolve(symbol, definitions, aliases)
    parameters = re.findall(r"%[-\w.]+", arguments)
    require(len(parameters) == 1, "unexpected cleanup helper signature")
    body = re.sub(re.escape(parameters[0]) + r"(?![-\w.])", "%state", body)
    codegen.cancellation(body, identity)


def check(body, identity, definitions, aliases, panic="unwind"):
    require(panic in ("abort", "unwind"), "unknown update panic profile")
    size, offsets = codegen.layout(identity)
    copies = re.findall(r"(%[-\w.]+) = alloca \[" + str(size) + r" x i8\],", body)
    require(len(copies) == 1, "missing/ambiguous update moved owner")
    copy = copies[0]
    pointers = {"%state": ("%state", 0), copy: (copy, 0)}
    for name, base, offset in re.findall(
            r"(%[-\w.]+) = getelementptr inbounds(?: nuw)? i8, ptr (%[-\w.]+), i64 (\d+)", body):
        require(name not in pointers and base in pointers, "unknown/duplicate update pointer")
        root, prior = pointers[base]
        pointers[name] = root, prior + int(offset)
    graph = codegen.blocks(body)
    queue = [(next(iter(graph)), "%state", frozenset())]
    visited = set()
    checked_helpers = set()
    updates = set()
    observers = set()
    exits = set()
    while queue:
        label, root, cleared = queue.pop()
        if (label, root, cleared) in visited:
            continue
        visited.add((label, root, cleared))
        require(label in graph and len(visited) < 10000, "invalid update graph")
        lines = graph[label]
        terminal = False
        for index, line in enumerate(lines):
            call = re.search(r'\b(?:call|invoke)\b.*@("[^"]+"|[-\w.$]+)\(', line)
            if call:
                symbol = call[1].strip('"')
                if symbol == "llvm.memcpy.p0.p0.i64":
                    require(root == "%state" and not cleared, "copy after update cleanup/move")
                    require(re.search(re.escape(copy) + r", ptr [^\n]*%state, i64 "
                                      + str(size) + r", i1 false\)", line), "update copy extent/source")
                    root = copy
                elif symbol.startswith("llvm.lifetime."):
                    require(symbol in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0")
                            and re.search(re.escape(copy) + r"\)", line), "unknown update lifetime")
                    if symbol == "llvm.lifetime.end.p0":
                        require(root == copy and cleared == offsets, "update lifetime ends uncleared")
                elif codegen.owner_drop(symbol, identity):
                    argument = re.search(r"(%[-\w.]+)\)", line)
                    require(argument and argument[1] in pointers, "unknown update cleanup pointer")
                    owner, offset = pointers[argument[1]]
                    require(owner == root and offset in offsets and offset not in cleared,
                            "wrong/duplicate update owner cleanup")
                    cleared = cleared | {offset}
                elif "drop_glue" in symbol or "drop_in_place" in symbol:
                    argument = re.search(r"(%[-\w.]+)\)", line)
                    require(argument and pointers.get(argument[1]) == (root, 0) and not cleared,
                            "wrong update helper owner")
                    if symbol not in checked_helpers:
                        helper(symbol, identity, definitions, aliases)
                        checked_helpers.add(symbol)
                    cleared = frozenset(offsets)
                elif ("brynja_mac_hmac" in symbol or "HardenedSha512T" in symbol) and re.search(
                        r"6update(?:17h[0-9a-f]+E|B\w+_)?$", symbol):
                    require(root == "%state" and not cleared, "update after cleanup/move")
                    require(panic == "abort" or re.search(r"\binvoke\b", line),
                            "unwind-capable update lacks cleanup edge")
                    argument = re.search(r"ptr [^,]*?(%[-\w.]+),", line)
                    expected = 0 if identity.startswith("sha3_") else 8
                    require(argument and pointers.get(argument[1]) == ("%state", expected),
                            "update not bound to inner owner")
                    updates.add((label, index))
                else:
                    require(codegen.panic_cleanup(symbol), "unknown update call")
            elif re.search(r"\b(call|invoke)\b", line):
                require(re.search(r"\b(?:call|invoke) void %observer\(\)", line)
                        and not cleared, "unknown/late update callback")
                require(panic == "abort" or re.search(r"\binvoke\b", line),
                        "unwind-capable callback lacks cleanup edge")
                observers.add((label, index))
            require(not re.search(r"\b(store|atomicrmw|cmpxchg)\b", line), "unexpected update write")
            if re.search(r"\binvoke\b", line):
                require(index + 1 < len(lines), "missing update invoke edges")
                edges = re.fullmatch("to label %" + LABEL + " unwind label %" + LABEL
                                     + r"(?:, ![-\w.]+ !\d+)*", lines[index + 1])
                require(edges, "invalid update invoke edges")
                queue += [(edge, root, cleared) for edge in edges.groups()]
                terminal = True
                break
            if line.startswith(("br ", "switch ")):
                text = line
                if line.startswith("switch "):
                    text = "\n".join(lines[index:])
                    require("]" in text, "unterminated update switch")
                    text = text.split("]", 1)[0]
                edges = re.findall("label %" + LABEL, text)
                require(edges, "missing update branch edges")
                queue += [(edge, root, cleared) for edge in edges]
                terminal = True
                break
            if line.startswith(("ret ", "resume ")):
                require(cleared == offsets, "update exits without both cleanup dispatches")
                exits.add(label)
                terminal = True
                break
            if line == "unreachable":
                require(codegen.fatal_cleanup_block(lines), "unknown update terminal")
                terminal = True
                break
        require(terminal, "unknown update terminator")
    require(exits and len(updates) == 1 and len(observers) == 1, "vacuous update/observer check")
