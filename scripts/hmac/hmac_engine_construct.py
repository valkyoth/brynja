"""Constructor owner creation, cleanup and returned-field transfer dispatch.

Source-bound callee contracts and safe Rust remain premises. This is not
compiler-created copy/register/spill erasure or a general LLVM interpreter.
"""
import re

import hmac_engine_codegen as codegen
import hmac_engine_final as final
from hmac_constructor_state import evaluate
from hmac_engine_construct_state import State
from hmac_engine_codegen import LABEL, require
from hmac_engine_final import VALUE


def start(symbol, identity):
    if identity.startswith("general"):
        rewritten = re.sub(r"3new(?=17h[0-9a-f]+E$|$)", "15finalize_secret", symbol)
        return rewritten != symbol and final.hash_finalizer(rewritten, identity)
    name = final.type_name(identity).removeprefix("Hardened")
    return bool(re.fullmatch(
        r"(?:_RNvXs\w*_NtCs\w+_15brynja_mac_hmac10algorithmsNtB\w+_"
        + str(len(name)) + name + r"NtNtB\w+_6sealed4Hash5start|"
        r"_ZN\d+_\$LT\$brynja_mac_hmac\.\.algorithms\.\." + name
        + r"\$u20\$as\$u20\$brynja_mac_hmac\.\.algorithms\.\.sealed\.\.Hash"
        r"\$GT\$5start17h[0-9a-f]+E)", symbol))


def mask(symbol):
    return bool(re.fullmatch(
        r"(?:_RNvNtCs\w+_15brynja_mac_hmac7scratch8mask_pad|"
        r"_ZN15brynja_mac_hmac7scratch8mask_pad17h[0-9a-f]+E)", symbol))


def is_update(symbol):
    return final.adapter_update(symbol) or bool(re.fullmatch(
        r"_ZN16brynja_hash_sha27general8hardened15HardenedSha512T6update17h[0-9a-f]+E",
        symbol))


def check(body, identity, panic="unwind", dynamic_tag=False):
    require(identity in codegen.IDENTITIES and panic in ("abort", "unwind"),
            "unknown constructor identity/panic profile")
    require(type(dynamic_tag) is bool, "unknown scalar tag profile")
    width, core_offset, fields = final.geometry(identity)
    allocs = {name: int(size) for name, size in re.findall(
        "(" + VALUE + r") = alloca \[(\d+) x i8\],", body)}
    ptrs = final.pointers(body, (*allocs, "%_0"))
    graph = codegen.blocks(body)
    roles = {}
    for token, role in enumerate(("hash", "inner", "outer")):
        names = [name for name, size in allocs.items()
                 if re.fullmatch("%" + role + r"(?:\.[-\w]+)*", name) and size == width]
        require(len(names) == 1, "constructor owner allocation missing: " + role)
        roles[names[0]] = token
    births = {}
    for label, lines in graph.items():
        for index, line in enumerate(lines):
            invocation = final.call(line)
            if invocation and start(invocation[0], identity):
                births[label, index] = len(births)
    require(len(births) == (0 if identity.startswith("sha3_") else 3),
            "constructor creation population changed")
    queue = [(next(iter(graph)), 0, None, State())]
    visited, successes, failures, normalizations, seen_births = set(), 0, 0, set(), set()

    def address(name):
        return ptrs.get(name, (name, 0))

    def no_owner(state, name):
        root = address(name)[0]
        require(root not in state.initializing and not any(row[0] == root for row in state.memory)
                and not any(base == root for base, _ in state.tag_fields),
                "constructor owner storage passed to auxiliary")

    def location(name, size):
        root, offset = address(name)
        require(offset >= 0 and (root == "%_0" and offset + size <= codegen.layout(identity)[0] + 8
                                or root in allocs and offset + size <= allocs[root]),
                "constructor owner copy escapes allocation")

    while queue:
        label, index, predecessor, state = queue.pop()
        key = label, index, predecessor, state.key()
        if key in visited:
            continue
        visited.add(key)
        require(label in graph and len(visited) < 30000, "invalid constructor graph")
        lines = graph[label]
        terminal = False
        while index < len(lines):
            line = lines[index]
            evaluate(line, state, address, predecessor)
            derived = re.match("(" + VALUE + r") = getelementptr.*?, ptr (" + VALUE + ")", line)
            if derived and (address(derived[2])[0] in state.initializing
                            or any(row[0] == address(derived[2])[0] for row in state.memory)
                            or any(root == address(derived[2])[0] for root, _ in state.tag_fields)):
                require(derived[1] in ptrs, "unresolved constructor owner arithmetic")
            if re.search(r"= (?:phi ptr|select .* ptr|ptrtoint|inttoptr|bitcast)", line):
                for name in re.findall(VALUE, line)[1:]:
                    no_owner(state, name)
            invocation = final.call(line)
            normal, unwind = None, None
            if invocation:
                symbol, args = invocation
                if (label, index) in births:
                    token = births[label, index]
                    destination = final.operand(args[0])
                    location(destination, width + (0 if identity.startswith("general") else 1))
                    output = address(destination)
                    unwind = state.clone()
                    success = state.clone()
                    if identity.startswith("general"):
                        require(args[1] == "i16 noundef " + identity.removeprefix("general"),
                                "general constructor parameter changed")
                        success.birth(output, width, token)
                        normal = [success]
                    else:
                        success.constants[(*output, 1)] = 0
                        success.birth((output[0], output[1] + 1), width, token)
                        failure = state.clone()
                        failure.constants[(*output, 1)] = 1
                        normal = [success, failure]
                    seen_births.add(token)
                elif symbol == "llvm.memcpy.p0.p0.i64":
                    dest, source = final.operand(args[0]), final.operand(args[1])
                    extent = re.fullmatch(r"i64 (\d+)", args[2])
                    require(extent, "variable constructor copy")
                    size = int(extent[1])
                    if state.overlap(address(source), size):
                        location(dest, size)
                    state.transfer(address(dest), address(source), size)
                elif symbol == "llvm.memset.p0.i64":
                    dest = final.operand(args[0])
                    extent = re.fullmatch(r"i64 (\d+)", args[2])
                    require(extent, "variable constructor memset")
                    size = int(extent[1])
                    state.forget_tags(address(dest), size)
                    require(address(dest)[0] not in state.initializing,
                            "overwrite of partially initialized scalar owner")
                    if dest in roles:
                        require(identity.startswith("sha3_") and size == width and args[1] == "i8 0",
                                "unknown inline constructor initialization")
                        state.birth(address(dest), width, roles[dest])
                        seen_births.add(roles[dest])
                    elif (identity.startswith("sha3_") and address(dest)[0] in roles
                          and address(dest)[1] == 1):
                        # Hosted LLVM can split the all-zero FIPS202 owner into
                        # its tail plus the leading state byte. Neither half
                        # alone creates an owner; all uses still need complete().
                        root = address(dest)[0]
                        require(size == width - 1 and args[1] == "i8 0"
                                and root not in state.initializing
                                and roles[root] not in state.born,
                                "incomplete/duplicate inline constructor initialization")
                        state.initializing.add(root)
                    else:
                        require(not state.overlap(address(dest), size), "constructor memset overwrites owner")
                elif symbol.startswith("llvm.lifetime."):
                    require(symbol in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"),
                            "unknown constructor lifetime")
                    root, offset = address(final.operand(args[-1]))
                    require(offset == 0, "interior constructor lifetime")
                    if symbol == "llvm.lifetime.end.p0":
                        state.end(root)
                    else:
                        require(root not in state.initializing
                                and not any(row[0] == root for row in state.memory),
                                "constructor restarts live storage")
                elif codegen.owner_drop(symbol, identity) or final.hash_finalizer(symbol, identity):
                    is_drop = codegen.owner_drop(symbol, identity)
                    root, offset = address(final.operand(args[0 if is_drop else 1]))
                    token = state.complete((root, offset - (core_offset if is_drop else 0)), width)
                    if not is_drop:
                        require(token == 0, "constructor finalizes inner/outer instead of normalization")
                        normalizations.add(token)
                    state.done.add(token)
                elif is_update(symbol):
                    name = final.operand(args[0])
                    token = state.complete(address(name), width)
                    require(name in roles and roles[name] == token, "constructor update owner role changed")
                    require(panic == "abort" or re.search(r"\binvoke\b", line),
                            "constructor update lacks unwind edge")
                else:
                    require(final.auxiliary(symbol) or mask(symbol) or codegen.panic_cleanup(symbol),
                            "unknown constructor call: " + symbol)
                    for arg in args:
                        if arg.startswith("ptr ") and re.search(VALUE + "$", arg):
                            no_owner(state, final.operand(arg))
            elif line.startswith("store "):
                store = re.match(r"store (ptr|i(\d+)) ([^,]+), ptr (" + VALUE + ")", line)
                require(store, "unsupported constructor store")
                size = (int(store[2]) + 7) // 8 if store[2] else 8
                value = state.value(store[3])
                if store[1] == "ptr" and store[3].startswith("%"):
                    no_owner(state, store[3])
                if isinstance(value, tuple):
                    location(store[4], size)
                state.store(address(store[4]), size, value)
                if dynamic_tag and store[3] == '%tag_bytes':
                    require(store[1] == 'i64', 'scalar constructor tag width changed')
                    state.tag_fields.add(address(store[4]))
                if address(store[4])[0] in state.initializing:
                    require(size == 1 and value == 0, "inline constructor leading byte changed")
                    root = address(store[4])[0]
                    state.initializing.remove(root)
                    state.birth(address(store[4]), width, roles[root])
                    seen_births.add(roles[root])
            elif re.search(r"\b(?:atomicrmw|cmpxchg)\b", line):
                require(False, "unexpected constructor atomic write")
            if re.search(r"\binvoke\b", line):
                require(index + 1 < len(lines), "missing constructor invoke edges")
                edges = re.fullmatch("to label %" + LABEL + " unwind label %" + LABEL
                                     + r"(?:, ![-\w.]+ !\d+)*", lines[index + 1])
                require(edges, "unparsed constructor invoke")
                queue += [(edges[1], 0, label, item) for item in normal or [state.clone()]]
                queue.append((edges[2], 0, label, unwind or state.clone()))
                terminal = True
                break
            if normal:
                queue += [(label, index + 1, predecessor, item) for item in normal]
                terminal = True
                break
            if line.startswith("br "):
                edges = re.findall("label %" + LABEL, line)
                condition = re.match("br i1 (" + VALUE + ")", line)
                require(len(edges) == (2 if condition else 1), "unparsed constructor branch")
                known = state.value(condition[1]) if condition else None
                require(known is None or known in (0, 1), "invalid constructor branch value")
                for edge, truth in zip(edges, (1, 0)):
                    if condition and known is not None and known != truth:
                        continue
                    child = state.clone()
                    if condition:
                        child.assign(condition[1], truth)
                    queue.append((edge, 0, label, child))
                terminal = True
                break
            if line.startswith("switch "):
                header = re.fullmatch(r"switch i\d+ (" + VALUE + "), label %" + LABEL + r" \[", line)
                require(header and "]" in lines[index + 1:], "unparsed constructor switch")
                end = lines.index("]", index + 1)
                cases = [re.fullmatch(r"i\d+ (-?\d+), label %" + LABEL, item)
                         for item in lines[index + 1:end]]
                require(all(cases), "unknown constructor switch case")
                value = state.value(header[1])
                require(value is None or isinstance(value, int), "noninteger constructor switch")
                for case in cases:
                    if value is None or value == int(case[1]):
                        child = state.clone()
                        child.assign(header[1], int(case[1]))
                        queue.append((case[2], 0, label, child))
                if value is None or value not in {int(case[1]) for case in cases}:
                    queue.append((header[2], 0, label, state.clone()))
                terminal = True
                break
            if line.startswith(("ret ", "resume ")):
                returned = state.constants.get(("%_0", 0, 1))
                if line.startswith("ret ") and returned == 0:
                    require(state.complete(("%_0", fields[0] + 8), width) == 1
                            and state.complete(("%_0", fields[1] + 8), width) == 2,
                            "constructor returned field provenance changed")
                    require(state.born - state.done == {1, 2}, "constructor leaked normalization owner")
                    if dynamic_tag:
                        tag_offset = 2088 if identity.startswith('sha3_') else 8
                        require(('%_0', tag_offset) in state.tag_fields,
                                'scalar constructor lost returned tag provenance')
                    successes += 1
                else:
                    require(line.startswith("resume ") or returned == 1, "unknown constructor return status")
                    require(state.born == state.done, "constructor exits with undispatched hash owner")
                    failures += 1
                terminal = True
                break
            if line == "unreachable":
                require(codegen.fatal_cleanup_block(lines), "unknown constructor terminal")
                terminal = True
                break
            index += 1
        require(terminal, "unknown constructor terminator: " + label + " " + repr(lines[-6:]))
    require(successes and failures and seen_births == {0, 1, 2} and normalizations == {0},
            "vacuous constructor owner check")
