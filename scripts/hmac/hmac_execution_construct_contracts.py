"""Reviewed non-unwinding leaf premise for constructor return temporaries."""
import hashlib
from pathlib import Path
import re

from hmac_engine_codegen import require
import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_execution_update as update

ROOT = Path(__file__).resolve().parents[2]
# clear_owned_region: empty-slice error or volatile clearing then value-only Ok.
# zeroize_region_volatile: safe slice iteration, write_volatile and compiler_fence.
# Neither has allocation, callbacks, indexing, fallible arithmetic or panic.
# Source drift requires review; these are integrity pins, not authentication.
CLEAR_INPUTS = {
    "crates/brynja-core/src/lib.rs":
        "43b8efd5409338f7cc68480fd8e5a65df55712912a1d3d1f0dff535b73d9d455",
    "crates/brynja-core/src/secret_memory.rs":
        "b3c23d66ac1b0528e0db4de8c804239733810df2070c67a342cfd39cfe1b11d5",
    "crates/brynja-core/src/secret_memory_volatile.rs":
        "44ee344e643429e45061dc8f3aacaf985789058c594ca7d54198077eaa8f756c",
}


def validate(root=ROOT):
    for name, digest in CLEAR_INPUTS.items():
        require(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest,
                "constructor non-unwinding clearing premise changed")


def non_unwinding(symbol):
    return bool(re.fullmatch(
        r"_RNvNtCs\w+_11brynja_core13secret_memory18clear_owned_region|"
        r"_ZN11brynja_core13secret_memory18clear_owned_region17h[0-9a-f]+E", symbol))


def update_adapter(symbol):
    return bool(re.fullmatch(
        r"_RNvXs_NtNtCs\w+_15brynja_mac_hmac9execution7adapterI\w+6sealed4Hash6updateCs\w+_"
        r"29brynja_hmac_execution_cleanup|"
        r"_ZN115_\$LT\$brynja_mac_hmac\.\.execution\.\.adapter\.\.Adapter\$LT\$A\$GT\$"
        r"\$u20\$as\$u20\$brynja_mac_hmac\.\.algorithms\.\.sealed\.\.Hash\$GT\$"
        r"6update17h[0-9a-f]+E", symbol))


def borrowed_update(symbol, identity, definitions, aliases):
    require(identity.startswith("general"), "unexpected constructor update adapter")
    arguments, body = common.resolve(symbol, definitions, aliases)
    formals = syntax.parameters(arguments)
    require(len(formals) == 3 and syntax.operand(formals[0]) == "%state"
            and syntax.operand(formals[1]) == "%input.0"
            and re.fullmatch(r"i64 [^%]*%input\.1", formals[2]), "update adapter formal binding")
    graph = common.blocks(body)
    entry = next(iter(graph.values()))
    invocation = syntax.call(entry[0])
    require(invocation and update.update_symbol(invocation[0], identity), "missing borrowed update")
    args = invocation[1]
    require(len(args) == 3 and syntax.operand(args[0]) == "%state"
            and syntax.operand(args[1]) == "%input.0"
            and re.fullmatch(r"i64 [^%]*%input\.1", args[2]), "borrowed update arguments changed")
    for line in [line for lines in graph.values() for line in lines][1:]:
        require(not syntax.call(line) and not re.search(r"\b(store|load|alloca|unreachable)\b", line)
                and not any(name in re.findall(syntax.VALUE, line) for name in
                            ("%state", "%input.0", "%input.1")),
                "update adapter has additional pointer effects")
    queue, returns = [(next(iter(graph)), frozenset())], 0
    while queue:
        label, trail = queue.pop()
        require(label in graph and label not in trail and len(trail) < 32,
                "cyclic/unknown update adapter graph")
        lines = graph[label]
        if lines[-1].startswith("ret i8 "):
            returns += 1
        else:
            edges = re.findall("label %" + common.LABEL, "\n".join(lines))
            require(edges, "unterminated update adapter")
            queue.extend((edge, trail | {label}) for edge in edges)
    require(returns, "vacuous borrowed update adapter")
