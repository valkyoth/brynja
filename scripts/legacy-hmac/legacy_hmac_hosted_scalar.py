"""Scalar constructor ownership and retained-state lifetime/cleanup composition.

Constructor ownership/scratch is checked before retained-state dispatch. Full
normalization-result provenance remains separate; this is not worker qualification.
"""
from functools import lru_cache
import re
from types import SimpleNamespace

import legacy_hmac_engine_codegen as legacy
import legacy_hmac_engine_final as final
import legacy_hmac_hosted_keyed as keyed
import legacy_hmac_hosted_constructor as constructor
import legacy_hmac_hosted_storage as storage
import legacy_hmac_hosted_construct as construct

require, syntax, V = keyed.require, keyed.syntax, keyed.V


class Retained(keyed.model.Admission):
    def __init__(self, body, names, compiler, identity, envelope):
        keyed.authority.model.Transfer.__init__(self, body, names, compiler)
        self.identity, self.compiled = identity, False
        self.compiler = compiler
        self.size, offsets = legacy.layout(identity)
        width, _, fields = final.geometry(identity)
        algorithm = 'Sha1' if identity == 'sha1' else 'Md5'
        prefix = '<brynja_legacy_hmac::engine::Engine<brynja_legacy_hmac::algorithms::' + algorithm + '>>::'
        self.terminals, self.consumers, origins = [], [], set()
        for operation, argument, arity in (('verify', 0, 4), ('secret', 1, 5)):
            calls = [(args, site) for symbol, args, site in self.calls if names.get(symbol) == prefix + operation]
            require(len(calls) == 1, 'scalar retained terminal population changed')
            args, site = calls[0]
            require(len(args) == arity, 'scalar terminal arity changed')
            dest = self.pointer(syntax.operand(args[argument]), site)
            require(dest and dest[1] == 0 and self.allocs[dest[0]] == self.size, 'scalar terminal geometry changed')
            moves = [(point, self.pointer(syntax.operand(data[1]), point))
                     for mode, point, pointer, data in self.writes if mode == 'copy'
                     and self.pointer(pointer, point) == dest and self.before(point, site)
                     and data[2:] == ['i64 ' + str(self.size), 'i1 false']]
            require(len(moves) == 1, 'scalar terminal move absent/ambiguous')
            move, origin = moves[0]
            origins.add(origin)
            self.terminals.append((dest[0], site, move))
            self.consumers.append((dest[0], site, argument))
        require(len(origins) == 1 and len({row[0] for row in self.terminals}) == 2, 'scalar terminal storage overlaps')
        origin = origins.pop()
        require(origin and origin[1] == 0 and self.allocs[origin[0]] == self.size, 'scalar retained geometry changed')
        self.owner, self.roots, self.results = origin[0], {origin[0]}, set()
        self.call_map = {point: (symbol, args) for symbol, args, point in self.calls}
        self.write_map = {point: (mode, dest, data) for mode, point, dest, data in self.writes}
        writes = [(mode, point, self.pointer(dest, point), data) for mode, point, dest, data in self.writes
                  if (p := self.pointer(dest, point)) and p[0] == self.owner]
        # Rust 1.90 unwind also copies six trailing padding bytes. They do not
        # carry a logical hash owner and are not asserted initialized secrets.
        padding = len(writes) == 4 and compiler == '1.90.0'
        require(len(writes) == 3 or padding, 'scalar retained initialization field population changed')
        self.initial = [point for _, point, _, _ in writes]
        last = [point for point in self.initial if all(other == point or self.before(other, point) for other in self.initial)]
        require(len(last) == 1, 'scalar initialization lacks completion point')
        self.cut = last[0]
        self.keyed = self.cut  # Capture read must precede completion of initialization.
        tag, tag_read = constructor.read_capture(self, envelope['loads'], 8, 'i64')
        initialized, sources = set(), set()
        for mode, point, dest, data in writes:
            require(dest[1] not in initialized and all(self.before(point, move) for _, _, move in self.terminals),
                    'scalar initial field repeated or late')
            initialized.add(dest[1])
            if dest[1] == 0:
                require(mode == 'store' and data == 'i64 ' + tag and self.before(tag_read, point),
                        'scalar retained tag width changed/read too late')
            elif padding and dest[1] == self.size - 6:
                source = self.pointer(syntax.operand(data[1]), point) if mode == 'copy' else None
                require(source and source[1] == 0 and self.allocs[source[0]] == 6
                        and data[2:] == ['i64 6', 'i1 false'], 'scalar trailing padding transfer changed')
            else:
                source = self.pointer(syntax.operand(data[1]), point) if mode == 'copy' else None
                require(dest[1] in offsets and mode == 'copy' and data[2:] == ['i64 ' + str(width), 'i1 false']
                        and source and source[1] == 0 and self.allocs[source[0]] == width,
                        'scalar hash-owner field transfer changed')
                sources.add(source[0])
        require(initialized == {0, *fields, *([self.size - 6] if padding else [])}
                and len(sources) == 2, 'scalar initialized owners overlap/missing')
        self.sources = sources
        self.initial_uses()
        self.terminal_handoffs()
        for root, point, argument in self.consumers:
            _, args = self.call_map[point]
            refs = [(i, self.pointer(syntax.operand(arg), point)) for i, arg in enumerate(args)
                    if arg.startswith('ptr ') and (p := self.pointer(syntax.operand(arg)))
                    and p[0] in {root, self.owner}]
            require(refs == [(argument, (root, 0))], 'scalar owner hidden in another terminal argument')


@lru_cache(maxsize=4)
def interpreter(identity, panic):
    require(identity in legacy.IDENTITIES and panic in ('abort', 'unwind'), 'unreviewed scalar retained profile')
    walker = legacy.load('hmac_hosted_scalar', 'legacy_hosted_scalar_' + identity + '_' + panic)
    # Isolate legacy identities/layouts; never mutate the modern-HMAC checker.
    walker.common = SimpleNamespace(LABEL=legacy.LABEL, owner_drop=legacy.owner_drop,
                                    panic_cleanup=legacy.flow.panic_cleanup)
    walker.syntax = SimpleNamespace(geometry=final.geometry, operand=syntax.operand,
                                    adapter_update=lambda symbol: legacy.adapter_update(symbol, identity))
    walker.cleanup = SimpleNamespace(helper=lambda symbol, owner, definitions, aliases:
                                     legacy.cleanup_helper(symbol, owner, definitions, aliases, panic))
    # The shared walk verifies exact update identity through this model's names.
    return walker


def check(body, names, compiler, identity, envelope, definitions, aliases, panic):
    model = Retained(body, names, compiler, identity, envelope)
    construct.check(model, envelope, panic)
    storage.check(model)
    for rhs, point in model.defs.values():
        loaded = re.match(r'load [^,]+, ptr (' + V + '),', rhs)
        if loaded and (pointer := model.pointer(loaded[1])) and pointer[0] == model.owner:
            require(False, 'scalar retained bytes read outside typed owner operations')
    for _, site, _ in model.terminals:
        require(panic == 'abort' or 'invoke ' in model.graph[site[0]][site[1]], 'scalar finalizer lost unwind edge')
    algorithm = 'Sha1' if identity == 'sha1' else 'Md5'
    expected = '<brynja_legacy_hmac::algorithms::' + algorithm + ' as brynja_legacy_hmac::algorithms::sealed::Hash>::update'
    # Presentation-only adaptation for the reused walk's typed update comparison.
    model.names = {symbol: ('<brynja_mac_hmac::algorithms::Sha' + identity[3:]
                           + ' as brynja_mac_hmac::algorithms::sealed::Hash>::update' if name == expected else name)
                   for symbol, name in names.items()}
    helpers = interpreter(identity, panic).check(model, identity, definitions, aliases, panic)
    model.names = names
    return model, helpers
