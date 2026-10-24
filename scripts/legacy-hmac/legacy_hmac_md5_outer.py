"""Conditional actual outer-pad conversion and descriptor lane provenance.

The inner owner's valid 128-byte region and earlier ipad contents are premises;
this does not prove the inner-result-to-owner binding, reports or final output.
Constructor/XOR semantics remain bound to unchanged source, not re-proved here.
"""
import hashlib
import re

import legacy_hmac_md5_keys as keys
import legacy_hmac_md5_outer_model as model

n = keys.normalization
phases, flow, syntax, require, VALUE = n.phases, n.flow, n.syntax, n.require, n.VALUE
Bits, Pointer = model.Bits, model.Pointer


class Check:
    constructor = staticmethod(keys.constructor)
    results = n.results

    def __init__(self, signature, body, llvm):
        self.body, self.graph, self.allocs = body, flow.blocks(body), phases.allocations(body)
        params = syntax.parameters(signature)
        self.inputs, self.control = syntax.operand(params[2]), syntax.operand(params[-1])
        require("readonly" in params[2] and "noalias" in params[2] and "dereferenceable(384)" in params[2],
                "outer activity input borrow changed")
        self.owner = phases.owner(self.allocs, "inner_owner", 16)
        self.pad = phases.owner(self.allocs, "pad", 512)
        self.outer = phases.owner(self.allocs, "outer_inputs", 256)
        self.final = phases.owner(self.allocs, "final_tags", 128)
        self.locals = {name for name, size in self.allocs.items() if size == 1}
        require(len(self.locals) == 1, "outer mask local missing/repeated")
        _, _, outer = n.results.sites(body)
        self.stop = outer[:2]
        self.capture = syntax.operand(outer[3][-1])
        self.result = syntax.operand(outer[3][0])
        self.start = phases.one(body, lambda name, args: name == "llvm.lifetime.start.p0" and
                               syntax.operand(args[-1]) == self.outer, "outer descriptor lifetime")[:2]
        phases.dominates(self.graph, self.start, self.stop)
        self.relevant = n.transport.errors.ancestors(self.graph, {self.stop[0]})
        # Bind the exposed pointer/length assumptions to the actual owner
        # stores, rather than seeding whichever unrelated address a loop uses.
        pointers = syntax.pointers(body, (self.owner,))
        stores = {}
        for label, lines in self.graph.items():
            for index, line in enumerate(lines):
                match = re.fullmatch(rf"store (ptr|i64) ({VALUE}), ptr ({VALUE}), align 8(?:, !.*)?", line)
                if match and pointers.get(match[3], (None,))[0] == self.owner:
                    offset = pointers[match[3]][1]
                    require(offset not in stores and (match[1], offset) in (("ptr", 0), ("i64", 8)),
                            "inner owner stores repeated/malformed")
                    phases.dominates(self.graph, (label, index), self.start)
                    stores[offset] = match[2]
        require(set(stores) == {0, 8}, "inner owner premise not backed by actual stores")
        require(len(set(stores.values())) == 2 and not set(stores.values()) &
                (set(self.allocs) | {self.inputs, self.control}), "inner owner premise aliases existing owners")
        self.seeds = {stores[0]: Pointer("inner-data"), stores[8]: Bits.integer(128, 64)}
        definition = re.search(rf"{re.escape(stores[0])} = inttoptr i64 ({VALUE}) to ptr", body)
        if definition:
            self.seeds[definition[1]] = Pointer("inner-data").bits()
        self.types = {}
        for dtype in set(re.findall(r'getelementptr(?: inbounds)?(?: nuw)? (%"[^"]+"),', body)):
            if dtype == '%"core::option::Option<md5_batch::Input<\'_>>"':
                require(dtype + " = type { ptr, [5 x i64] }" in llvm, "outer input element geometry changed")
                self.types[dtype] = 48
            elif dtype == '%"core::option::Option<brynja_hash_core::bit_string::BitString<\'_>>"':
                require(dtype + " = type { ptr, [3 x i64] }" in llvm, "outer descriptor element geometry changed")
                self.types[dtype] = 32
        self.temporaries = {name for name, size in self.allocs.items() if size in (23, 24, 32)}
        self.writable = self.temporaries | self.locals | {self.outer}
        self.lifetimes = self.writable | {self.final, self.result}
        self.visited, self.scenarios = set(), 0

    def run(self, mask, failure=None):
        state = model.State(self, mask, failure)
        success = state.walk()
        self.visited.update(state.visited)
        self.scenarios += 1
        require(success == (failure is None) and state.failed == (failure is not None), "outer failure/dispatch mismatch")
        if success:
            require(self.outer in state.live and self.pad in state.live and self.owner in state.live,
                    "outer descriptor/prefix/owner expired before dispatch")
            require(state.constructed == [lane for lane in range(8) if mask & (1 << lane)], "outer lane population changed")
            require(state.xors == [offset for offset in range(512) if mask & (1 << (offset // 64))],
                    "outer prefix conversion skips/repeats bytes")
            for offset in range(512):
                before = Bits.token(("ipad", offset), 8)
                expected = Bits(tuple(("not", bit) if mask & (1 << (offset // 64)) and 106 & (1 << i) else bit
                                      for i, bit in enumerate(before.data)))
                require(state.memory.load(Pointer(self.pad, offset), "i8") == expected, "outer prefix byte provenance changed")
            for lane in range(8):
                pointer = state.memory.load(Pointer(self.outer, lane * 32), "ptr")
                if mask & (1 << lane):
                    payload = tuple(bit for i in range(lane * 32 + 8, lane * 32 + 32)
                                    for bit in state.memory.cells.get((self.outer, i), (None,) * 8))
                    require(pointer == Pointer("inner-data", lane * 16) and payload == Bits.token(("descriptor", lane), 192).data,
                            "outer descriptor lane/payload provenance changed")
                else:
                    require(pointer == Bits.integer(0, 64), "inactive outer lane not absent")
            require(all(state.memory.cells.get((self.final, i)) == (0,) * 8 for i in range(128)),
                    "final digest destination not freshly zeroed")
            for offset, name in zip((0, 8, 16, 24), (self.pad, self.outer, self.final, self.control)):
                require(state.memory.load(Pointer(self.capture, offset), "ptr") == Pointer(name),
                        "outer dispatch does not consume constructed owners")
        return state


def validate(fixture, llvm):
    keys.probes(fixture)
    n.pads.probes(fixture)
    for name, digest in {**n.pads.PINS, keys.SOURCE: keys.DIGEST}.items():
        require(hashlib.sha256((phases.rows.contracts.ROOT / name).read_bytes()).hexdigest() == digest,
                "outer constructor/XOR semantic premise changed")
    definitions, aliases = flow.definitions_and_aliases(llvm)
    checks = []
    for operation in ("authenticate", "authenticate_secret", "verify"):
        check = Check(*phases.rows.method(definitions, aliases, operation)[1], llvm)
        for mask in range(256):
            check.run(mask)
        for lane in range(8):
            for position in (lane * 64, lane * 64 + 63):
                check.run(255, ("xor", position))
            check.run(255, ("constructor", lane))
        checks.append(check)
    return checks
