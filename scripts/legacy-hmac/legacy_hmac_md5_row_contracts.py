"""Narrow source-bound non-refilling destructors; integrity, not approval.

OwnedSecretRegion/initialization Drop only clear their referenced storage.
Md5Owner Drop clears only its fields. Workspace drop glue is independently
walked below and must dispatch all eight fixed-size lane destructors. These
premises do not qualify the surrounding CPU kernels, callbacks or scope paths.
"""
import hashlib
from pathlib import Path
import re
from types import SimpleNamespace

import legacy_hmac_execution_iterator as legacy

shared, flow, syntax, require = legacy.shared, legacy.flow, legacy.syntax, legacy.require
ROOT = Path(__file__).resolve().parents[2]
PINS = {
    "crates/brynja-core/src/lib.rs": "43b8efd5409338f7cc68480fd8e5a65df55712912a1d3d1f0dff535b73d9d455",
    "crates/brynja-core/src/secret_memory.rs": "b3c23d66ac1b0528e0db4de8c804239733810df2070c67a342cfd39cfe1b11d5",
    "crates/brynja-core/src/secret_memory_volatile.rs": "44ee344e643429e45061dc8f3aacaf985789058c594ca7d54198077eaa8f756c",
    "crates/brynja-legacy-md5/src/owner.rs": "1e1f9b2ad97d42b0d52fd04de473180a41ada8d6f52c154075f2ea7217b29947",
}
walker = shared.load("hmac_execution_iterator", "legacy_md5_workspace_walk")
_integer = walker.integer
walker.integer = lambda text, values: int(text == "true") if text in ("true", "false") else _integer(text, values)


def helper(symbol, definitions, aliases):
    require(workspace_drop(symbol), "unexpected nested MD5 workspace helper")
    signature, body = flow.resolve(symbol, definitions, aliases)
    parameters = syntax.parameters(signature)
    require(len(parameters) == 1 and "dereferenceable(912)" in parameters[0], "workspace destructor geometry")
    return syntax.operand(parameters[0]), body


walker.cleanup = SimpleNamespace(leaf=lambda name: "md5" if shared.owner_drop(name, "md5") else None, helper=helper)


def validate(root=ROOT):
    for name, digest in PINS.items():
        require(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest,
                "MD5 non-refilling destructor premise changed: " + name)


def region_drop(symbol):
    return bool(re.fullmatch(
        r"_RNvXs\w*_NtCs\w+_11brynja_core13secret_memoryNtB\w+_(?:17OwnedSecretRegion|26SecretRegionInitialization)"
        r"NtNtNtCs\w+_4core3ops4drop4Drop4drop|"
        r"_ZN\d+_\$LT\$brynja_core\.\.secret_memory\.\.(?:OwnedSecretRegion|SecretRegionInitialization)"
        r"\$u20\$as\$u20\$core\.\.ops\.\.drop\.\.Drop\$GT\$4drop17h[0-9a-f]+E", symbol))


def workspace_drop(symbol):
    return bool(re.fullmatch(
        r"_RINvNtCs\w+_4core3ptr(?:9drop_glue|13drop_in_place)NtNtNtNtCs\w+_17brynja_legacy_md5"
        r"5batch18hardened_execution8in_place9WorkspaceECs\w+_18brynja_legacy_hmac|"
        r"_ZN4core3ptr\d+drop_in_place\$LT\$brynja_legacy_md5\.\.batch\.\.hardened_execution"
        r"\.\.in_place\.\.Workspace\$GT\$17h[0-9a-f]+E", symbol))


def workspace(symbol, definitions, aliases, panic, llvm):
    parameter, body = helper(symbol, definitions, aliases)
    expected = frozenset(("md5", 8 + lane * 113) for lane in range(8))
    types = {}
    for name in set(re.findall(r'getelementptr(?: inbounds)?(?: nuw)? (%"[^"]+"),', body)):
        require(name == '%"brynja_legacy_md5::owner::Md5Owner"', "unknown workspace array element")
        fields = re.findall(r"^" + re.escape(name) + r" = type \{ ([^}\n]+) \}$", llvm, re.M)
        require(len(fields) == 1, "missing workspace element layout")
        parts = fields[0].split(", ")
        require(all(re.fullmatch(r"\[\d+ x i8\]", part) for part in parts)
                and sum(int(part[1:].split()[0]) for part in parts) == 113, "workspace element is not 113 bytes")
        types[name] = 113
    for exceptional in (False, True):
        outcomes = walker.walk(body, parameter, 0, {}, definitions, aliases, panic, unwinding=exceptional, types=types)
        require(outcomes and all(events == expected for _, events in outcomes), "workspace misses/repeats lane cleanup")
