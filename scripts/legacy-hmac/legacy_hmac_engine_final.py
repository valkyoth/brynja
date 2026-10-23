"""Bind the shared owner-transfer interpreter to exact legacy hash identities."""
from functools import lru_cache
import re
from types import SimpleNamespace
import legacy_hmac_engine_codegen as codegen

# Load dependencies first by exact path, so the shared interpreter's imports
# cannot resolve to a file added under the legacy family directory.
codegen.load("hmac_engine_update")


def geometry(identity):
    _, offsets = codegen.layout(identity)
    return (433 if identity == "sha1" else 113), 0, tuple(sorted(offsets))


def hash_finalizer(symbol, identity):
    family, name = ("18brynja_legacy_sha1", "12HardenedSha1") if identity == "sha1" else ("17brynja_legacy_md5", "11HardenedMd5")
    return bool(re.fullmatch(
        r"(?:_RNvM(?:s[0-9a-z]+_)?NtCs\w+_" + family + r"8hardenedNtB\w+_" + name
        + r"|_ZN" + family + r"8hardened" + name + r")(?:15finalize_secret|20finalize_bits_secret)(?:17h[0-9a-f]+E)?", symbol))


@lru_cache(maxsize=2)
def interpreter(identity):
    codegen.require(identity in codegen.IDENTITIES, "unknown legacy finalizer identity")
    module = codegen.load("hmac_engine_final", "legacy_final_graph_" + identity)
    module.codegen = SimpleNamespace(
        IDENTITIES=codegen.IDENTITIES, owner_drop=codegen.owner_drop,
        blocks=codegen.flow.blocks, resolve=codegen.flow.resolve,
        panic_cleanup=codegen.flow.panic_cleanup, fatal_cleanup_block=codegen.flow.fatal_cleanup_block,
    )
    module.update = SimpleNamespace(helper=lambda symbol, owner, definitions, aliases:
                                    codegen.cleanup_helper(symbol, owner, definitions, aliases, "unwind"))
    module.geometry = geometry
    module.hash_finalizer = hash_finalizer
    module.adapter_update = lambda symbol: codegen.adapter_update(symbol, identity)
    # Current emitted legacy adapters inline their closures. Unknown outlined
    # closures must be reviewed, not accepted from a broad substring match.
    module.finish_closure = lambda symbol: False
    return module


def check(body, identity, definitions, aliases, panic):
    interpreter(identity).check(body, identity, definitions, aliases, panic)
