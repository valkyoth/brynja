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
    labels = [match.group(1) for match in starts]
    if len(labels) != len(set(labels)):
        fail("MIR caller contains duplicate basic-block labels")
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


def call_definition(body: str) -> tuple[str, str, str, str | None, str] | None:
    """Return destination, target, arguments, successor, and unwind edges."""
    calls = list(re.finditer(
        r"(?m)^\s*(?P<destination>.+?)\s*=\s*(?P<call>.+)\)\s*"
        r"->\s*\[(?P<edges>[^\n]*)\];?\s*$",
        body,
    ))
    if len(calls) > 1:
        fail("MIR basic block contains multiple call terminators")
    if not calls:
        return None
    call = calls[0]
    opening = call.group("call").find("(")
    if opening < 1:
        fail("MIR call terminator has no callable boundary")
    target = call.group("call")[:opening + 1].strip()
    arguments = call.group("call")[opening + 1:]
    returned = re.search(rf"\breturn:\s*({BLOCK})\b", call.group("edges"))
    return (
        call.group("destination").strip(),
        target,
        arguments,
        returned.group(1) if returned else None,
        call.group("edges"),
    )


def exact_calls(blocks: dict[str, str], target: str) -> list[tuple[str, str]]:
    if not isinstance(target, str) or not target.strip() or not target.endswith("("):
        fail("MIR cleanup target must be a nonempty call boundary")
    calls = []
    for block, body in blocks.items():
        call = call_definition(body)
        if call is not None and call[1] == target:
            calls.append((block, first_argument(call[2])))
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


def place_root(place: str) -> tuple[str, bool]:
    """Return one MIR place root and whether the destination is projected."""
    roots = set(re.findall(LOCAL, place))
    if len(roots) != 1:
        fail("MIR destination place is absent or ambiguous")
    root = next(iter(roots))
    return root, place.strip() != root


def apply_definition(
    state: tuple[set[str], set[str]], destination: str, expression: str,
) -> tuple[set[str], set[str]]:
    """Apply a plain assignment to definite and possible provenance."""
    definite, possible = map(set, state)
    root, projected = place_root(destination)
    references = set(re.findall(LOCAL, expression)) & possible
    source = explicit_derivation(expression)
    if projected:
        if root in possible:
            fail("owner-derived place is redefined before lifecycle exit")
        if references:
            fail("owner-derived alias escapes into a projected place")
        return definite, possible
    if root == "_1":
        fail("registered owner receiver is reassigned")
    if references and source not in possible:
        fail("owner-derived value escapes through an unmodeled assignment")
    if source in definite:
        definite.add(root)
    else:
        definite.discard(root)
    if source in possible:
        possible.add(root)
    else:
        possible.discard(root)
    return definite, possible


def statement_state(
    body: str, incoming: tuple[set[str], set[str]],
) -> tuple[set[str], set[str]]:
    """Apply non-call MIR definitions to must/may owner provenance."""
    state = tuple(map(set, incoming))
    for line in body.splitlines():
        if re.match(r"^\s*.+?\s*=\s*.+\)\s*->\s*\[", line):
            continue
        deinit = re.match(r"^\s*deinit\((?P<place>.+)\);\s*$", line)
        if deinit is not None:
            root, _ = place_root(deinit.group("place"))
            if root in state[1]:
                fail("owner-derived place is deinitialized before lifecycle exit")
            continue
        if "asm!" in line and set(re.findall(LOCAL, line)) & state[1]:
            fail("owner-derived value enters an unmodeled assembly statement")
        match = re.match(r"^\s*(?P<destination>.+?)\s*=\s*(?P<expression>.+);\s*$", line)
        if match is not None:
            state = apply_definition(
                state, match.group("destination"), match.group("expression"),
            )
            continue
        references = set(re.findall(LOCAL, line)) & state[1]
        safe_observation = re.match(
            r"^\s*(?:switchInt|assert|StorageLive|StorageDead|FakeRead|Retag|"
            r"PlaceMention|AscribeUserType)\b",
            line,
        )
        if references and safe_observation is None:
            fail("owner-derived value enters an unmodeled MIR statement")
    return state


def call_edge_state(
    state: tuple[set[str], set[str]], destination: str, may_alias_owner: bool,
) -> tuple[set[str], set[str]]:
    """Apply an untrusted successful call-result definition."""
    definite, possible = map(set, state)
    root, projected = place_root(destination)
    if projected:
        if root in possible:
            fail("call result overwrites an owner-derived place")
        return definite, possible
    if root == "_1":
        fail("registered owner receiver is reassigned")
    definite.discard(root)
    if may_alias_owner:
        possible.add(root)
    else:
        possible.discard(root)
    return definite, possible


def block_successors(blocks: dict[str, str], block: str) -> set[str]:
    targets = set(re.findall(rf"\b{BLOCK}\b", blocks[block]))
    missing = targets - set(blocks)
    if missing:
        fail(f"MIR caller references unknown basic blocks: {sorted(missing)}")
    return targets


def owner_states(
    blocks: dict[str, str], cleanup_block: str, cleanup_target: str,
) -> dict[str, tuple[set[str], set[str]]]:
    """Compute must/may `_1` provenance and reject unmodeled alias effects."""
    incoming = {"bb0": ({"_1"}, {"_1"})}
    pending = ["bb0"]
    while pending:
        block = pending.pop()
        state = statement_state(blocks[block], incoming[block])
        call = call_definition(blocks[block])
        if call is not None:
            _, target, arguments, _, _ = call
            references = set(re.findall(LOCAL, target + arguments)) & state[1]
            if references and not (block == cleanup_block and target == cleanup_target):
                fail("owner-derived value enters a non-sanitizer call")
        for successor in block_successors(blocks, block):
            edge_state = tuple(map(set, state))
            if call is not None and successor == call[3]:
                edge_state = call_edge_state(
                    edge_state, call[0], block == cleanup_block and call[1] == cleanup_target,
                )
            previous = incoming.get(successor)
            merged = edge_state if previous is None else (
                previous[0] & edge_state[0], previous[1] | edge_state[1],
            )
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
    cleanup_call = call_definition(blocks[cleanup_block])
    if cleanup_call is None or not re.search(r"\bunwind unreachable\b", cleanup_call[4]):
        fail("cleanup target must be compiler-proven non-unwinding")
    incoming = owner_states(blocks, cleanup_block, target)
    if cleanup_block not in incoming:
        fail("cleanup target is unreachable")
    cleanup_state = statement_state(blocks[cleanup_block], incoming[cleanup_block])
    if argument_root(argument, cleanup_state[0]) != "_1":
        fail("cleanup target does not sanitize the registered owner")
    graph, exits = control_flow(blocks)
    nodes = reachable(graph)
    reachable_exits = exits & nodes
    if not reachable_exits:
        fail("MIR caller has no reachable lifecycle exit")
    dominance = dominators(graph, nodes)
    if any(cleanup_block not in dominance[exit_name] for exit_name in reachable_exits):
        fail("cleanup does not dominate every lifecycle exit")
