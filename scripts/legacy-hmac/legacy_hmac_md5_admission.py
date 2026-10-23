"""MD5 tag/authority admission up to workspace construction, not its readiness.

Exact unsigned range predicate covers all usize inputs. Independent downstream
type probes bind rejection layouts and the executor backend niche. Stop before
Workspace::new: later readiness, output and quarantine remain separate checks.
"""
import re

import legacy_hmac_md5_rows as rows
from legacy_hmac_execution_admission_contracts import stores

flow, syntax, require = rows.flow, rows.syntax, rows.require
VALUE = rows.common.VALUE


def probe(definitions, aliases, name):
    matches = [symbol for symbol in (*definitions, *aliases)
               if re.search("30brynja_legacy_hmac_md5_cleanup" + str(len(name)) + name
                            + r"(?:17h[0-9a-f]+E)?$", symbol)]
    require(len(matches) == 1, "missing/ambiguous MD5 admission probe: " + name)
    return flow.resolve(matches[0], definitions, aliases)[1]


def layout(fixture, target):
    definitions, aliases = flow.definitions_and_aliases(fixture)
    tag = stores(probe(definitions, aliases, "tag_rejection"))
    unavailable = stores(probe(definitions, aliases, "authority_rejection"))
    require(tag == {0: 1, 16: 2} and unavailable == {0: 3, 16: 2}, "MD5 selection rejection layout changed")
    require(list(flow.blocks(probe(definitions, aliases, "portable_backend")).values()) == [["ret i8 2"]],
            "MD5 portable backend niche changed")
    backend = list(flow.blocks(probe(definitions, aliases, "backend")).values())
    require(len(backend) == 1 and len(backend[0]) == 3, "backend observation gained control flow")
    gep, load, ret = backend[0]
    match = re.fullmatch(rf"({VALUE}) = getelementptr inbounds(?: nuw)? i8, ptr %executor, i64 9", gep)
    require(match, "MD5 backend field changed")
    read = re.match(rf"({VALUE}) = load i8, ptr {re.escape(match[1])}, align 1(?:,|$)", load)
    require(read and ret == "ret i8 " + read[1], "MD5 backend read changed")
    forwarding = list(flow.blocks(probe(definitions, aliases, "select")).values())
    require(len(forwarding) == 1 and len(forwarding[0]) == 2 and forwarding[0][-1] == "ret void",
            "MD5 constructor consumer does not directly forward")
    call = syntax.call(forwarding[0][0])
    require(call and call[0] == target and len(call[1]) == 3
            and [syntax.operand(arg) for arg in call[1][:2]] == ["%_0", "%executor"]
            and re.fullmatch(r"i64(?: noundef)? %bytes", call[1][2]),
            "MD5 constructor consumer changed arguments")
    return tag, unavailable


def check(signature, body, valid_tag, backend, rejected):
    parameters = syntax.parameters(signature)
    require(len(parameters) == 3 and syntax.operand(parameters[0]) == "%_0"
            and syntax.operand(parameters[1]) == "%executor", "MD5 constructor signature changed")
    require(re.fullmatch(r"i64(?: noundef)? " + VALUE, parameters[2]), "MD5 tag width type changed")
    tag = parameters[2].split()[-1]
    graph = flow.blocks(body)
    label, seen = next(iter(graph)), set()
    pointers, values, output, allocations = {"%_0": ("result", 0), "%executor": ("executor", 0)}, {}, {}, {}
    ranged = loaded = False
    while label not in seen:
        seen.add(label)
        require(label in graph, "unknown MD5 admission edge")
        for line in graph[label]:
            definition = re.fullmatch(rf"({VALUE}) = (.*)", line)
            invocation = syntax.call(line)
            store = re.match(rf"store i8 (-?\d+), ptr ({VALUE}), align \d+", line)
            branch = re.fullmatch(rf"br i1 ({VALUE}), label %{flow.LABEL}, label %{flow.LABEL}", line)
            jump = re.fullmatch(r"br label %" + flow.LABEL, line)
            if definition:
                name, expression = definition.groups()
                allocation = re.fullmatch(r"alloca \[(\d+) x i8\], align \d+", expression)
                gep = re.fullmatch(rf"getelementptr inbounds(?: nuw)? i8, ptr ({VALUE}), i64 (\d+)", expression)
                read = re.match(rf"load i8, ptr ({VALUE}), align 1(?:,|$)", expression)
                comparison = re.fullmatch(rf"icmp(?: samesign)? eq i8 ({VALUE}), 2", expression)
                range_check = re.fullmatch(rf"icmp ult i64 ({VALUE}), 7", expression)
                if allocation:
                    pointers[name] = (name, 0)
                    allocations[name] = int(allocation[1])
                elif expression == f"add i64 {tag}, -10":
                    require(not ranged, "repeated MD5 range offset")
                    values[name] = "tag-offset"
                elif range_check:
                    require(values.get(range_check[1]) == "tag-offset" and not ranged, "changed MD5 tag admission")
                    ranged = True
                    values[name] = valid_tag
                elif gep:
                    require(gep[1] in pointers, "unbound MD5 admission pointer")
                    root, offset = pointers[gep[1]]
                    pointers[name] = root, offset + int(gep[2])
                elif read:
                    require(valid_tag and ranged and not loaded and pointers.get(read[1]) == ("executor", 9),
                            "premature/repeated/unbound backend read")
                    loaded = True
                    values[name] = backend
                elif comparison:
                    require(loaded and comparison[1] in values and isinstance(values[comparison[1]], int),
                            "unbound MD5 backend comparison")
                    values[name] = values[comparison[1]] == 2
                else:
                    require(False, "unknown MD5 pre-workspace instruction: " + line)
            elif store:
                root, offset = pointers.get(store[2], (None, None))
                require(root == "result" and offset not in output and 0 <= offset < 24,
                        "admission writes outside rejection result")
                output[offset] = int(store[1])
            elif invocation:
                symbol, args = invocation
                if symbol == "llvm.lifetime.start.p0":
                    require(len(args) in (1, 2) and syntax.operand(args[-1]) in allocations,
                            "unbound MD5 admission lifetime")
                    if len(args) == 2:
                        require(args[0] == "i64 " + str(allocations[syntax.operand(args[-1])]),
                                "MD5 admission lifetime extent changed")
                else:
                    require(re.fullmatch(
                        r"_RNvMs_NtNtNtCs\w+_17brynja_legacy_md55batch18hardened_execution8in_placeNtB\w+_9Workspace3new|"
                        r"_ZN17brynja_legacy_md55batch18hardened_execution8in_place9Workspace3new17h[0-9a-f]+E", symbol),
                        "unexpected call before MD5 workspace admission")
                    require(valid_tag and loaded and backend != 2 and not output and len(args) == 2
                            and allocations.get(syntax.operand(args[0])) == 912
                            and syntax.operand(args[1]) == "%executor", "unapproved/substituted MD5 workspace")
                    return
            elif branch:
                require(branch[1] in values and isinstance(values[branch[1]], bool), "unbound MD5 admission predicate")
                label = branch[2] if values[branch[1]] else branch[3]
                break
            elif jump:
                label = jump[1]
                break
            elif line == "ret void":
                require(ranged and (not valid_tag or backend == 2) and output == rejected
                        and loaded == valid_tag, "wrong MD5 early rejection")
                return
            else:
                require(False, "unknown MD5 admission effect: " + line)
        else:
            require(False, "unterminated MD5 admission path")
    require(False, "cyclic MD5 admission path")


def validate(fixture, llvm):
    definitions, aliases = flow.definitions_and_aliases(llvm)
    target, (signature, body) = rows.method(definitions, aliases, "with_tag_length")
    tag, unavailable = layout(fixture, target)
    for valid in (False, True):
        for backend in (0, 1, 2):
            check(signature, body, valid, backend, unavailable if valid else tag)
