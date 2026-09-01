#!/usr/bin/env python3
"""Conservative optimized-MIR owner-cleanup data-flow and dominance checks."""

from __future__ import annotations

import re


LOCAL = r"_\d+"
BLOCK = r"bb\d+"


class MirCleanupFlowError(RuntimeError):
    """The selected MIR function does not prove mandatory owner cleanup."""


def fail(message: str) -> None:
    raise MirCleanupFlowError(message)


def function_sections(mir: str) -> list[str]:
    starts = [match.start() for match in re.finditer(r"(?m)^fn ", mir)]
    return [
        mir[start:starts[index + 1] if index + 1 < len(starts) else len(mir)]
        for index, start in enumerate(starts)
    ]


def exact_function(mir: str, header_parts: tuple[str, ...]) -> str:
    if not header_parts or any(not isinstance(part, str) or not part.strip() for part in header_parts):
        fail("MIR caller header must contain nonempty strings")
    matches = [
        section for section in function_sections(mir)
        if all(part in section.splitlines()[0] for part in header_parts)
    ]
    if len(matches) != 1:
        fail(f"MIR caller is absent or ambiguous: {header_parts}")
    return matches[0]


def basic_blocks(function: str) -> dict[str, str]:
    starts = list(re.finditer(rf"(?m)^\s*({BLOCK})(?: \(cleanup\))?: \{{\s*$", function))
    blocks = {}
    for index, match in enumerate(starts):
        stop = starts[index + 1].start() if index + 1 < len(starts) else len(function)
        blocks[match.group(1)] = function[match.end():stop]
    if "bb0" not in blocks:
        fail("MIR caller has no entry basic block")
    return blocks


def first_argument(arguments: str) -> str:
    depths = {"(": 0, "[": 0, "<": 0}
    closing = {")": "(", "]": "[", ">": "<"}
    for index, character in enumerate(arguments):
        if character in depths:
            depths[character] += 1
        elif character in closing and depths[closing[character]]:
            depths[closing[character]] -= 1
        elif character == "," and not any(depths.values()):
            return arguments[:index].strip()
    return arguments.strip()


def exact_calls(blocks: dict[str, str], target: str) -> list[tuple[str, str]]:
    if not isinstance(target, str) or not target.strip() or not target.endswith("("):
        fail("MIR cleanup target must be a nonempty call boundary")
    pattern = re.compile(
        rf"(?m)^\s*{LOCAL}\s*=\s*"
        + re.escape(target)
        + r"(?P<arguments>[^\n]*)\)\s*->\s*\["
    )
    calls = [
        (block, first_argument(match.group("arguments")))
        for block, body in blocks.items()
        for match in pattern.finditer(body)
    ]
    if len(calls) != 1:
        fail("cleanup target must have exactly one resolved call")
    return calls


def explicit_derivation(expression: str) -> str | None:
    sources = re.findall(LOCAL, expression)
    if len(set(sources)) != 1:
        return None
    stripped = expression.strip()
    source = sources[0]
    place = rf"(?:{re.escape(source)}|\(\*{re.escape(source)}\))(?:\.\d+)*"
    if not (
        re.fullmatch(rf"(?:move|copy)\s+{place}", stripped)
        or re.fullmatch(rf"&(?:raw\s+)?(?:mut\s+)?{place}", stripped)
    ):
        return None
    return source


def statement_state(body: str, incoming: set[str]) -> set[str]:
    """Apply non-call MIR definitions to a definite owner-provenance set."""
    state = set(incoming)
    for line in body.splitlines():
        if re.match(rf"^\s*{LOCAL}\s*=\s*.+\)\s*->\s*\[", line):
            continue
        match = re.match(rf"^\s*({LOCAL})\s*=\s*(.+);\s*$", line)
        if match is None:
            continue
        destination, expression = match.groups()
        if destination == "_1":
            fail("registered owner receiver is reassigned")
        source = explicit_derivation(expression)
        if source in state:
            state.add(destination)
        else:
            state.discard(destination)
    return state


def call_definition(body: str) -> tuple[str, str | None] | None:
    """Return a call destination and its successful-return block."""
    calls = list(re.finditer(
        rf"(?m)^\s*({LOCAL})\s*=\s*[^\n]+\)\s*->\s*\[(?P<edges>[^\n]*)\]",
        body,
    ))
    if len(calls) > 1:
        fail("MIR basic block contains multiple call terminators")
    if not calls:
        return None
    destination = calls[0].group(1)
    if destination == "_1":
        fail("registered owner receiver is reassigned")
    returned = re.search(rf"\breturn:\s*({BLOCK})\b", calls[0].group("edges"))
    return destination, returned.group(1) if returned else None


def block_successors(blocks: dict[str, str], block: str) -> set[str]:
    return {
        target for target in re.findall(rf"\b{BLOCK}\b", blocks[block])
        if target in blocks
    }


def definite_owner_states(blocks: dict[str, str]) -> dict[str, set[str]]:
    """Compute locals rooted in `_1` on every path reaching each block."""
    incoming = {"bb0": {"_1"}}
    pending = ["bb0"]
    while pending:
        block = pending.pop()
        state = statement_state(blocks[block], incoming[block])
        call = call_definition(blocks[block])
        for successor in block_successors(blocks, block):
            edge_state = set(state)
            if call is not None and successor == call[1]:
                edge_state.discard(call[0])
            previous = incoming.get(successor)
            merged = edge_state if previous is None else previous & edge_state
            if previous != merged:
                incoming[successor] = merged
                pending.append(successor)
    return incoming


def argument_root(argument: str, derived: set[str]) -> str | None:
    sources = set(re.findall(LOCAL, argument))
    if len(sources) != 1:
        return None
    source = next(iter(sources))
    return "_1" if source in derived and explicit_derivation(argument) else None


def control_flow(blocks: dict[str, str]) -> tuple[dict[str, set[str]], set[str]]:
    graph = {block: set() for block in blocks}
    exits = set()
    for block, body in blocks.items():
        graph[block].update(target for target in re.findall(rf"\b{BLOCK}\b", body) if target in blocks)
        if re.search(r"(?m)^\s*return;", body):
            exit_name = f"normal:{block}"
            graph[block].add(exit_name)
            graph[exit_name] = set()
            exits.add(exit_name)
        if re.search(r"(?m)^\s*(?:resume|abort);", body) or re.search(
            r"\bunwind (?:continue|terminate(?:\([^)]*\))?)", body,
        ):
            exit_name = f"unwind:{block}"
            graph[block].add(exit_name)
            graph[exit_name] = set()
            exits.add(exit_name)
    if not exits:
        fail("MIR caller has no normal or unwind exit")
    return graph, exits


def reachable(graph: dict[str, set[str]]) -> set[str]:
    observed = set()
    pending = ["bb0"]
    while pending:
        node = pending.pop()
        if node in observed:
            continue
        observed.add(node)
        pending.extend(graph[node] - observed)
    return observed


def dominators(graph: dict[str, set[str]], nodes: set[str]) -> dict[str, set[str]]:
    predecessors = {node: set() for node in nodes}
    for source in nodes:
        for destination in graph[source] & nodes:
            predecessors[destination].add(source)
    result = {node: set(nodes) for node in nodes}
    result["bb0"] = {"bb0"}
    changed = True
    while changed:
        changed = False
        for node in nodes - {"bb0"}:
            incoming = predecessors[node]
            updated = {node} | (set.intersection(*(result[item] for item in incoming)) if incoming else set())
            if updated != result[node]:
                result[node] = updated
                changed = True
    return result


def require_owner_cleanup(mir: str, header_parts: tuple[str, ...], target: str) -> None:
    function = exact_function(mir, header_parts)
    blocks = basic_blocks(function)
    cleanup_block, argument = exact_calls(blocks, target)[0]
    incoming = definite_owner_states(blocks)
    if cleanup_block not in incoming:
        fail("cleanup target is unreachable")
    cleanup_state = statement_state(blocks[cleanup_block], incoming[cleanup_block])
    if argument_root(argument, cleanup_state) != "_1":
        fail("cleanup target does not sanitize the registered owner")
    graph, exits = control_flow(blocks)
    nodes = reachable(graph)
    reachable_exits = exits & nodes
    if not reachable_exits:
        fail("MIR caller has no reachable lifecycle exit")
    dominance = dominators(graph, nodes)
    if any(cleanup_block not in dominance[exit_name] for exit_name in reachable_exits):
        fail("cleanup does not dominate every lifecycle exit")
