"""Execute bounded, concrete metadata paths of emitted iterator destruction.

No crypto/data interpretation: only public cursor/option metadata and exact
core/scratch cleanup boundaries. Actual helper bodies are resolved recursively.
"""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_execution_admission_contracts as admission
import hmac_execution_drop as cleanup

require, VALUE = common.require, syntax.VALUE


def integer(text, values):
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    value = values.get(text)
    require(isinstance(value, int), "unknown iterator metadata integer: " + text)
    return value


def array_types(llvm):
    """Only homogeneous i64 structs: no unmodelled ABI padding."""
    result = {}
    for name, fields in re.findall(r'^(%"[^"]+") = type \{ ([^}\n]+) \}$', llvm, re.M):
        if not name.startswith(('%"core::mem::maybe_uninit::', '%"core::option::Option<')):
            continue
        parts = fields.split(", ")
        require(all(re.fullmatch(r"(?:\[\d+ x i64\]|i64)", part) for part in parts),
                "unknown iterator array type layout")
        result[name] = sum(8 if part == "i64" else int(part[1:].split()[0]) * 8 for part in parts)
    return result


def metadata(line, values, memory, predecessor, types):
    """Strict metadata instruction evaluator; returns False for non-metadata."""
    definition = re.match("(" + VALUE + r") = (.*)", line)
    if not definition:
        return False
    name, expression = definition.groups()
    gep = re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? (i8|\[(\d+) x i8\]|%"[^"]+"), ptr ('
                       + VALUE + r"), i64 (" + VALUE + r"|-?\d+)", expression)
    load = re.match(r"load i(\d+), ptr (" + VALUE + "),", expression)
    arithmetic = re.fullmatch(r"(add|sub)(?: nuw)?(?: nsw)? i(\d+) ("
                              + VALUE + r"|-?\d+), (" + VALUE + r"|-?\d+)", expression)
    comparison = re.fullmatch(r"icmp(?: samesign)? (eq|ne|ult|ugt|ule|uge) i(\d+) ("
                              + VALUE + r"|-?\d+), (" + VALUE + r"|-?\d+)", expression)
    phi = re.fullmatch(r"phi (?:i\d+|ptr) (.*)", expression)
    if gep:
        base = values.get(gep[3])
        require(isinstance(base, tuple) and base[0] == "ptr", "unknown iterator pointer")
        stride = 1 if gep[1] == "i8" else int(gep[2]) if gep[2] else types.get(gep[1])
        require(stride, "unbound iterator array stride")
        offset = integer(gep[4], values) * stride
        values[name] = ("ptr", base[1] + offset)
    elif load:
        pointer = values.get(load[2])
        require(pointer and pointer[0] == "ptr", "unknown iterator load pointer")
        key = pointer[1], int(load[1]) // 8
        require(key in memory, "iterator reads unbound metadata")
        values[name] = memory[key]
    elif arithmetic or comparison:
        match = arithmetic or comparison
        bits = int(match[2])
        left, right = (integer(text, values) % (1 << bits) for text in match.group(3, 4))
        if arithmetic:
            if not match[4].startswith("%") and int(match[4]) < 0:
                right = int(match[4])
            result = left + right if match[1] == "add" else left - right
            require(0 <= result < (1 << bits), "iterator arithmetic wraps")
        else:
            result = int({"eq": left == right, "ne": left != right, "ult": left < right,
                          "ugt": left > right, "ule": left <= right, "uge": left >= right}[match[1]])
        values[name] = result
    elif phi:
        choices = re.findall(r"\[ ([-\w%.]+), %" + common.LABEL + r" \]", phi[1])
        selected = [operand for operand, label in choices if label == predecessor]
        require(len(selected) == 1, "unbound iterator phi predecessor")
        value = values.get(selected[0]) if selected[0].startswith("%") else integer(selected[0], values)
        require(value is not None, "unknown iterator phi input")
        values[name] = value
    else:
        return False
    return True


def walk(body, parameter, base, memory, definitions, aliases, panic, unwinding=False,
         done=frozenset(), depth=0, types=None):
    require(depth < 5, "recursive iterator destructor")
    graph = common.blocks(body)
    queue = [(next(iter(graph)), None, {parameter: ("ptr", base)}, done, unwinding, ())]
    results, steps = [], 0
    while queue:
        label, predecessor, values, events, exceptional, trail = queue.pop()
        key = label, tuple(sorted(values.items())), events, exceptional
        require(key not in trail and len(trail) < 120, "cyclic iterator destruction")
        trail += (key,)
        steps += 1
        require(label in graph and steps < 2000, "oversized iterator destruction")
        lines, terminal = graph[label], False
        for index, line in enumerate(lines):
            if metadata(line, values, memory, predecessor, types or {}):
                continue
            invocation = syntax.call(line)
            if invocation:
                symbol, args = invocation
                if common.panic_cleanup(symbol):
                    require(exceptional and index + 1 < len(lines) and lines[index + 1] == "unreachable",
                            "iterator fatal exemption on normal entry")
                    terminal = True
                    break
                require(len(args) == 1, "iterator destructor callee arity")
                pointer = values.get(syntax.operand(args[0]))
                require(pointer and pointer[0] == "ptr", "unbound iterator destruction pointer")
                kind = cleanup.leaf(symbol)
                if kind:
                    event = kind, pointer[1]
                    require(event not in events, "duplicate iterator destruction")
                    outcomes = [("ret", events | {event}), ("resume", events | {event})]
                else:
                    formal, nested = cleanup.helper(symbol, definitions, aliases)
                    outcomes = walk(nested, formal, pointer[1], memory, definitions, aliases,
                                    panic, exceptional, events, depth + 1, types)
                if re.search(r"\binvoke\b", line):
                    edges = re.fullmatch("to label %" + common.LABEL + " unwind label %"
                                         + common.LABEL + r"(?:, ![-\w.]+ !\d+)*", lines[index + 1])
                    require(edges, "unparsed iterator invoke")
                    queue.extend((edges[1 if outcome == "ret" else 2], label, dict(values), next_events,
                                  exceptional or outcome == "resume", trail)
                                 for outcome, next_events in outcomes)
                    terminal = True
                    break
                normal = [item for outcome, item in outcomes if outcome == "ret"]
                require(normal and all(item == normal[0] for item in normal), "ambiguous iterator cleanup")
                if panic == "unwind":
                    results.extend((outcome, item) for outcome, item in outcomes if outcome == "resume")
                events = normal[0]
            elif line.startswith("switch "):
                header = re.fullmatch(r"switch i(\d+) (" + VALUE + "), label %"
                                      + common.LABEL + r" \[", line)
                require(header and "]" in lines[index + 1:], "unparsed iterator switch")
                end = lines.index("]", index + 1)
                cases = [re.fullmatch(r"i\d+ (-?\d+), label %" + common.LABEL, item)
                         for item in lines[index + 1:end]]
                require(all(cases), "unknown iterator switch case")
                modulus = 1 << int(header[1])
                value = integer(header[2], values) % modulus
                selected = [case[2] for case in cases if int(case[1]) % modulus == value]
                require(len(selected) <= 1, "ambiguous iterator switch")
                queue.append((selected[0] if selected else header[3], label, dict(values),
                              events, exceptional, trail))
                terminal = True
                break
            elif line.startswith("br "):
                direct = re.fullmatch("br label %" + common.LABEL, line)
                branch = re.fullmatch("br i1 (" + VALUE + "), label %" + common.LABEL
                                      + ", label %" + common.LABEL + r"(?:, ![-\w.]+ !\d+)*", line)
                require(direct or branch, "unknown iterator branch")
                condition = integer(branch[1], values) if branch else None
                require(condition in (None, 0, 1), "invalid iterator branch condition")
                target = direct[1] if direct else branch[2 if condition else 3]
                queue.append((target, label, dict(values), events, exceptional, trail))
                terminal = True
                break
            elif line.startswith(("ret void", "resume ")):
                results.append(("ret" if line == "ret void" else "resume", events))
                terminal = True
                break
            elif (re.fullmatch(VALUE + r" = landingpad \{ ptr, i32 \}", line)
                  or re.match(VALUE + r" = phi \{ ptr, i32 \} ", line)
                  or line in ("cleanup", "filter [0 x ptr] zeroinitializer")):
                pass
            else:
                require(False, "unsupported iterator destructor instruction: " + line)
        require(terminal, "unterminated iterator destructor")
    require(results, "vacuous iterator destruction")
    return results


def check(symbol, identity, definitions, aliases, compiler, panic, cursor, long_key, route,
          unwinding=False, types=None):
    """Empty caches plus the exact unconsumed suffix of the three-entry array."""
    require(cursor in range(4) and route in (0, 1) and identity in common.IDENTITIES
            and compiler in ("1.90.0", "1.99.1") and panic in ("abort", "unwind"),
            "invalid iterator metadata profile")
    shape, discriminator, absent, cached, start = admission.geometry(identity, compiler)
    offset = 32 if identity.startswith("sha3_") else 16
    memory = {(0, 1 if identity.startswith("sha3_") else 16): 1,
              (offset, 8): cursor, (offset + 8, 8): 3}
    expected = set()
    for token in range(5):
        present = token < (3 if long_key else 2)
        memory[start + token * shape.stride + discriminator, 8] = (
            route if present else absent if token == 2 else cached)
        if cursor <= token < 3 and present:
            expected |= {(shape.core_kind, start + token * shape.stride + shape.core),
                         (shape.scratch_kind, start + token * shape.stride)}
    parameter, body = cleanup.helper(symbol, definitions, aliases)
    outcomes = walk(body, parameter, 0, memory, definitions, aliases, panic, unwinding, types=types)
    require(all(events == expected for _, events in outcomes),
            "iterator destructor does not clear exactly its remaining owners")
    return outcomes
