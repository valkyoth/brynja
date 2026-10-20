"""Callee identities and layout premises for accelerated constructor admission."""
import re

import hmac_execution_drop as cleanup
import hmac_execution_final_contracts as final
from hmac_engine_codegen import require


def factory(symbol, identity):
    if identity.startswith("general"):
        if re.fullmatch(
                r"(?:_RNvMNtNtCs\w+_15brynja_mac_hmac9execution8backendsNtB\w+_6Source4sha2|"
                r"_ZN15brynja_mac_hmac9execution8backends6Source4sha217h[0-9a-f]+E)", symbol):
            return "session"
        renamed = re.sub(r"3new(?=17h[0-9a-f]+E$|$)", "15finalize_secret", symbol)
        if renamed != symbol and final.hash_finalizer(renamed, identity):
            return "hash"
    else:
        name = ("Sha3_" + identity[5:] if identity.startswith("sha3_")
                else "Sha" + identity[3:])
        if re.fullmatch(
                r"(?:_RNvXs\w*_NtNtCs\w+_15brynja_mac_hmac9execution8backendsNtNtB\w+_"
                r"10algorithms" + str(len(name)) + name + r"NtB\w+_7Backend6create|"
                r"_ZN\d+_\$LT\$brynja_mac_hmac\.\.algorithms\.\." + name
                + r"\$u20\$as\$u20\$brynja_mac_hmac\.\.execution\.\.backends"
                r"\.\.Backend\$GT\$6create17h[0-9a-f]+E)", symbol):
            return "hash"
    return None


def geometry(identity, compiler):
    shape = cleanup.layout(identity)
    sha3 = identity.startswith("sha3_")
    discriminator = 576 if sha3 else 704
    error = 2 if sha3 else 3 if compiler == "1.90.0" else -1
    returned_error = 3 if sha3 and compiler == "1.90.0" else (
        -1 if sha3 else 4 if compiler == "1.90.0" else -2)
    pool = 64 if sha3 else 32
    return shape, discriminator, error, returned_error, pool


def block_bytes(identity):
    if identity.startswith("sha3_"):
        return 200 - 2 * int(identity[5:]) // 8
    return 64 if identity in ("sha224", "sha256") else 128


def constant(state, address, size):
    """Read a little-endian metadata field, including split integer stores."""
    root, offset = address
    values = []
    for byte in range(offset, offset + size):
        pieces = [(value >> (8 * (byte - start))) & 255
                  for (base, start, width), value in state.constants.items()
                  if base == root and start <= byte < start + width]
        if len(pieces) != 1:
            return None
        values.append(pieces[0])
    return sum(value << (8 * index) for index, value in enumerate(values))


def pool_handoff(state, identity, compiler, long_key):
    shape, discriminator, absent, nested_absent, start = geometry(identity, compiler)
    live = {0, 1, 2} if long_key else {0, 1}
    require(state.born - state.done == live, "admission pool has missing/extra owners")
    for token in live:
        require(state.complete(("%states", start + token * shape.stride), shape.stride) == token,
                "admission pool order or owner bytes changed")
    cursor = 32 if identity.startswith("sha3_") else 16
    require(constant(state, ("%states", 0), 1) == 1
            and constant(state, ("%states", cursor), 8) == 0
            and constant(state, ("%states", cursor + 8), 8) == 3,
            "admission iterator active-range metadata changed")
    for index in (3, 4):
        require(constant(state, ("%states", start + index * shape.stride + discriminator), 8)
                == nested_absent % (1 << 64), "admission cached iterator state is not empty")
    if not long_key:
        require(constant(state, ("%states", start + 2 * shape.stride + discriminator), 8)
                == absent % (1 << 64), "short-key admission has nonempty third state")
