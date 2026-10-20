"""Exact accelerated finalizer boundaries; hash internals remain callee premises."""
import re

import hmac_engine_final as syntax
import hmac_execution_drop as cleanup
from hmac_engine_codegen import require


def hash_finalizer(symbol, identity):
    name = ("Sha512T" if identity.startswith("general") else
            "Sha3_" + identity[5:] if identity.startswith("sha3_") else "Sha" + identity[3:])
    path = (r"16brynja_hash_sha38hardened11accelerated5fixed" if identity.startswith("sha3_")
            else r"16brynja_hash_sha218hardened_execution"
            + ("7general" if identity.startswith("general") else "5named"))
    prefix = r"(?:_RNvM(?:\w*_)?Nt(?:Nt)+Cs\w+_" + path + r"NtB\w+_|_ZN" + path + ")"
    return bool(re.fullmatch(prefix + str(len(name)) + name
                             + r"(?:15finalize_secret|20finalize_bits_secret)"
                             + r"(?:17h[0-9a-f]+E)?", symbol))


def adapter(symbol):
    return bool(re.fullmatch(
        r"_RINvXs\w*_NtNtCs\w+_15brynja_mac_hmac9execution8backends\w+7Backend10finish_cpu"
        r"\w+ECs\w+_29brynja_hmac_execution_cleanup"
        r"|_ZN\d+_\$LT\$brynja_mac_hmac\.\.(?:algorithms|general).*"
        r"\$u20\$as\$u20\$brynja_mac_hmac\.\.execution\.\.backends\.\.Backend\$GT\$10finish_cpu17h[0-9a-f]+E",
        symbol)) or syntax.finish_closure(symbol)


def update(symbol):
    return bool(re.fullmatch(
        r"_RNvXs\w*_NtNtCs\w+_15brynja_mac_hmac9execution8backends\w+10update_cpu"
        r"|_ZN\d+_\$LT\$brynja_mac_hmac\.\.(?:algorithms|general).*"
        r"\$u20\$as\$u20\$brynja_mac_hmac\.\.execution\.\.backends\.\.Backend\$GT\$10update_cpu17h[0-9a-f]+E"
        r"|_RNvM(?:\w*_)?NtNtCs\w+_16brynja_hash_sha218hardened_execution7generalNtB\w+_7Sha512T6update"
        r"|_ZN16brynja_hash_sha218hardened_execution7general7Sha512T6update17h[0-9a-f]+E",
        symbol))


def events(identity, token):
    shape = cleanup.layout(identity)
    return frozenset(((shape.core_kind, token * shape.stride + shape.core),
                      (shape.scratch_kind, token * shape.stride)))


def select(memory, pointer, kind, shape):
    root, offset = pointer
    relative = shape.core if kind == shape.core_kind else 0
    found = {token for base, start, token in memory if base == root and start + relative == offset}
    require(len(found) == 1, "missing/ambiguous accelerated finalizer owner")
    return next(iter(found))


def destruction(symbol, pointer, memory, done, identity, definitions, aliases, route, panic, unwinding):
    shape = cleanup.layout(identity)
    root, offset = pointer
    rows = [row for row in memory if row[0] == root and row[1] >= offset]
    require(rows, "cleanup helper lacks tracked accelerated owner")
    first = min(rows, key=lambda row: row[1])
    base = first[2] * shape.stride - first[1] + offset
    require(all(token * shape.stride == base + start - offset for _, start, token in rows),
            "cleanup helper owner ordering changed")
    parameter, body = cleanup.helper(symbol, definitions, aliases)
    discriminator = {token * shape.stride + shape.discriminator: route for _, _, token in rows}
    return cleanup.walk(body, parameter, base, discriminator, done, definitions, aliases,
                        panic=panic, unwinding=unwinding)
