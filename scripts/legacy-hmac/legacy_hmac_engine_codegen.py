"""Legacy cancellation/update ownership dispatch, not copy/register erasure."""
import importlib.util
from pathlib import Path
import re
import sys

SHARED = Path(__file__).resolve().parents[1] / "hmac"


def load(name, alias=None):
    """Resolve trusted parser modules by exact path before dependent imports."""
    path = SHARED / (name + ".py")
    key = alias or name
    if key in sys.modules:
        module = sys.modules[key]
        if Path(module.__file__).resolve() != path:
            raise ValueError("unexpected shared compiler checker origin")
        return module
    spec = importlib.util.spec_from_file_location(key, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[key] = module
    spec.loader.exec_module(module)
    return module


flow = load("hmac_engine_codegen")
require, LABEL = flow.require, flow.LABEL
IDENTITIES = ("sha1", "md5")
OPERATIONS = ("cancel", "construct", "update_cancel", "public", "secret", "verify",
              "public_bits", "secret_bits", "verify_bits")


def layout(identity):
    require(identity in IDENTITIES, "unknown legacy identity")
    return (880, {8, 441}) if identity == "sha1" else (240, {8, 121})


def owner_drop(symbol, identity):
    family, owner = ("18brynja_legacy_sha1", "9Sha1Owner") if identity == "sha1" else ("17brynja_legacy_md5", "8Md5Owner")
    return bool(re.fullmatch(
        r"_RNvXs_NtCs\w+_" + family + r"5ownerNtB\w+_" + owner
        + r"NtNtNtCs\w+_4core3ops4drop4Drop4drop|"
        + r"_ZN\d+_\$LT\$" + family.lstrip("0123456789") + r"\.\.owner\.\."
        + owner.lstrip("0123456789") + r"\$u20\$as\$u20\$core\.\.ops\.\.drop\.\.Drop\$GT\$4drop17h[0-9a-f]+E", symbol))


def adapter_update(symbol, identity):
    name = "Sha1" if identity == "sha1" else "Md5"
    return bool(re.fullmatch(
        r"_RNvXs\w*_NtCs\w+_18brynja_legacy_hmac10algorithmsNtB\w+_" + str(len(name)) + name
        + r"NtNtB\w+_6sealed4Hash6update|"
        r"_ZN\d+_\$LT\$brynja_legacy_hmac\.\.algorithms\.\." + name
        + r"\$u20\$as\$u20\$brynja_legacy_hmac\.\.algorithms\.\.sealed\.\.Hash\$GT\$6update17h[0-9a-f]+E", symbol))


def emitted(llvm):
    definitions, aliases = flow.definitions_and_aliases(llvm)
    result = {}
    for identity in IDENTITIES:
        for operation in OPERATIONS:
            suffix = "33brynja_legacy_hmac_engine_cleanup" + str(len(identity)) + identity + str(len(operation)) + operation
            names = [name for name in (*definitions, *aliases) if re.search(suffix + r"(?:17h\w+E)?$", name)]
            require(len(names) == 1, "missing/ambiguous legacy consumer " + identity + "::" + operation)
            result[identity, operation] = flow.resolve(names[0], definitions, aliases)[1]
    return result, definitions, aliases


def cleanup_helper(symbol, identity, definitions, aliases, panic):
    name = "Sha1" if identity == "sha1" else "Md5"
    require(("drop_glue" in symbol or "drop_in_place" in symbol) and "brynja_legacy_hmac" in symbol
            and (str(len(name)) + name in symbol or "algorithms.." + name in symbol),
            "unexpected legacy cleanup helper identity")
    arguments, body = flow.resolve(symbol, definitions, aliases)
    parameters = re.findall(r"%[-\w.]+", arguments)
    require(len(parameters) == 1, "unexpected cleanup helper signature")
    body = re.sub(re.escape(parameters[0]) + r"(?![-\w.])", "%state", body)
    lifecycle(body, identity, definitions, aliases, panic, helper=True)


def lifecycle(body, identity, definitions, aliases, panic, updating=False, helper=False):
    require(panic in ("abort", "unwind"), "unknown lifecycle panic profile")
    size, offsets = layout(identity)
    copies = re.findall(r"(%[-\w.]+) = alloca \[" + str(size) + r" x i8\],", body)
    require(len(copies) <= 1 and (not updating or len(copies) == 1), "unexpected moved owner allocation")
    copy = copies[0] if copies else None
    pointers = {"%state": ("%state", 0)}
    if copy:
        pointers[copy] = (copy, 0)
    for name, base, offset in re.findall(
            r"(%[-\w.]+) = getelementptr inbounds(?: nuw)? i8, ptr (%[-\w.]+), i64 (\d+)", body):
        require(name not in pointers and base in pointers, "unresolved lifecycle pointer")
        root, prior = pointers[base]
        pointers[name] = (root, prior + int(offset))
    # No alternate pointer arithmetic or aliases may bypass the fixed geometry.
    for line in body.splitlines():
        if "getelementptr" in line:
            name = line.strip().split(" = ", 1)[0]
            require(name in pointers, "unparsed lifecycle pointer arithmetic")
        require(not re.search(r"= (?:phi ptr|select .* ptr|ptrtoint|inttoptr|bitcast)", line), "untracked lifecycle alias")
    graph = flow.blocks(body)
    queue = [(next(iter(graph)), "%state", frozenset())]
    visited, exits, updates, observers = set(), set(), set(), set()
    while queue:
        label, root, cleared = queue.pop()
        if (label, root, cleared) in visited:
            continue
        visited.add((label, root, cleared))
        require(label in graph and len(visited) < 10000, "invalid lifecycle graph")
        lines, terminal = graph[label], False
        for index, line in enumerate(lines):
            call = re.search(r'\b(?:call|invoke)\b.*@("[^"]+"|[-\w.$]+)\(', line)
            if call:
                symbol = call[1].strip('"')
                if symbol == "llvm.memcpy.p0.p0.i64":
                    require(copy and root == "%state" and not cleared, "copy after cleanup/move")
                    require(re.search(re.escape(copy) + r", ptr [^\n]*%state, i64 " + str(size) + r", i1 false\)", line),
                            "owner copy identity/extent changed")
                    root = copy
                elif symbol.startswith("llvm.lifetime."):
                    require(copy and symbol in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0")
                            and re.search(re.escape(copy) + r"\)", line), "unknown owner lifetime")
                    if symbol == "llvm.lifetime.end.p0":
                        require(root == copy and cleared == offsets, "owner lifetime ends without cleanup")
                elif owner_drop(symbol, identity):
                    argument = re.search(r"(%[-\w.]+)\)", line)
                    require(argument and argument[1] in pointers, "unknown cleanup pointer")
                    base, offset = pointers[argument[1]]
                    require(base == root and offset in offsets and offset not in cleared, "wrong/duplicate owner cleanup")
                    cleared = cleared | {offset}
                elif "drop_glue" in symbol or "drop_in_place" in symbol:
                    require(not helper, "recursive cleanup helper")
                    argument = re.search(r"(%[-\w.]+)\)", line)
                    require(argument and pointers.get(argument[1]) == (root, 0) and not cleared, "wrong helper owner")
                    cleanup_helper(symbol, identity, definitions, aliases, panic)
                    cleared = frozenset(offsets)
                elif updating and adapter_update(symbol, identity):
                    argument = re.search(r"ptr [^,]*?(%[-\w.]+),", line)
                    require(root == "%state" and not cleared and argument
                            and pointers.get(argument[1]) == ("%state", 8), "update not bound to live inner owner")
                    require(panic == "abort" or re.search(r"\binvoke\b", line), "update missing unwind edge")
                    updates.add((label, index))
                else:
                    require(flow.panic_cleanup(symbol), "unknown lifecycle call: " + symbol)
            elif re.search(r"\b(call|invoke)\b", line):
                require(updating and re.search(r"\b(?:call|invoke) void %observer\(\)", line)
                        and not cleared, "unknown/late lifecycle observer")
                require(panic == "abort" or re.search(r"\binvoke\b", line), "observer missing unwind edge")
                observers.add((label, index))
            require(not re.search(r"\b(store|atomicrmw|cmpxchg)\b", line), "unexpected lifecycle write")
            if re.search(r"\binvoke\b", line):
                require(index + 1 < len(lines), "missing lifecycle invoke edges")
                edges = re.fullmatch("to label %" + LABEL + " unwind label %" + LABEL + r"(?:, ![-\w.]+ !\d+)*", lines[index + 1])
                require(edges, "invalid lifecycle invoke edges")
                queue += [(edge, root, cleared) for edge in edges.groups()]
                terminal = True
                break
            if line.startswith(("br ", "switch ")):
                text = line if line.startswith("br ") else "\n".join(lines[index:]).split("]", 1)[0]
                edges = re.findall("label %" + LABEL, text)
                require(edges, "missing lifecycle branch edges")
                queue += [(edge, root, cleared) for edge in edges]
                terminal = True
                break
            if line.startswith(("ret ", "resume ")):
                require(cleared == offsets, "exit without both hash-owner cleanup dispatches")
                exits.add(label)
                terminal = True
                break
            if line == "unreachable":
                require(flow.fatal_cleanup_block(lines), "unknown lifecycle terminal")
                terminal = True
                break
        require(terminal, "unknown lifecycle terminator")
    require(exits and len(updates) == int(updating) and len(observers) == int(updating), "vacuous lifecycle check")
