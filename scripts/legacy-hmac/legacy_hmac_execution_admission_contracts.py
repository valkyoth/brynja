"""Independent compiler ABI probes and the real constructor caller binding."""
import re

import legacy_hmac_execution_final as final

flow, syntax, require = final.flow, final.model.final, final.require
VALUE = final.model.SSA


def consumer(definitions, aliases, name):
    pattern = r"36brynja_legacy_hmac_execution_cleanup" + str(len(name)) + name + r"(?:17h\w+E)?$"
    matches = [symbol for symbol in (*definitions, *aliases) if re.search(pattern, symbol)]
    require(len(matches) == 1, "missing/ambiguous constructor probe: " + name)
    return flow.resolve(matches[0], definitions, aliases)[1]


def stores(body):
    graph = flow.blocks(body)
    require(len(graph) == 1, "conditional constructor ABI probe")
    pointers = syntax.pointers(body, ("%_0",))
    result = {}
    for line in next(iter(graph.values())):
        store = re.fullmatch(rf"store i8 (-?\d+), ptr ({VALUE}), align \d+", line)
        if store:
            root, offset = pointers.get(store[2], (None, None))
            require(root == "%_0" and offset not in result, "overlapping/unbound ABI probe store")
            result[offset] = int(store[1])
        else:
            require(line == "ret void" or re.fullmatch(rf"{VALUE} = getelementptr inbounds(?: nuw)? i8, ptr %_0, i64 \d+", line),
                    "unrecognized constructor ABI probe instruction")
    require(next(iter(graph.values()))[-1] == "ret void", "ABI probe has no return")
    return result


def forwarding(body, target, tag):
    require(tag in ("%bytes", "20"), "unknown constructor forwarding tag")
    graph = flow.blocks(body)
    require(len(graph) == 1, "constructor consumer gained control flow")
    lines = next(iter(graph.values()))
    require(len(lines) == 2 and lines[-1] == "ret void", "constructor consumer no longer directly forwards")
    symbol, args = syntax.call(lines[0])
    require(symbol == target and len(args) == 5, "constructor consumer dispatch changed")
    require([syntax.operand(arg) for arg in args[:3]] == ["%_0", "%executor", "%key.0"]
            and re.fullmatch(r"i64(?: noundef)? %key\.1", args[3])
            and re.fullmatch(r"i64(?: noundef)? " + re.escape(tag), args[4]), "constructor argument forwarding changed")


def validate(fixture, target):
    definitions, aliases = flow.definitions_and_aliases(fixture)
    for name, size in (("owner_size", 912), ("stream_size", 448)):
        require(list(flow.blocks(consumer(definitions, aliases, name)).values()) == [[f"ret i64 {size}"]],
                "constructor/stream geometry changed")
    for name, expected in (("start_rejection", {0: 2, 441: 2}),
                           ("constructor_tag_rejection", {0: 1, 904: 2}),
                           ("constructor_authority_rejection", {0: 3, 904: 2})):
        require(stores(consumer(definitions, aliases, name)) == expected, "constructor rejection ABI changed: " + name)
    require(list(flow.blocks(consumer(definitions, aliases, "portable_report")).values()) == [
        ["ret { i1, i8 } { i1 false, i8 2 }"]], "portable report ABI changed")
    cache = stores(consumer(definitions, aliases, "empty_iterator_cache"))
    require(len(cache) == 1 and cache.get(441) in (-1, 3), "iterator cache niche changed")
    forwarding(consumer(definitions, aliases, "construct"), target, "%bytes")
    return cache[441]
