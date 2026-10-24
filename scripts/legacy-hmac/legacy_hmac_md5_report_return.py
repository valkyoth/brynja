"""Bind accepted inner/outer counters to actual returned report fields.

Conditional on reaching the report field writes. Immutable SSA transport is
checked, including all output-address uses; success-discriminant/every-return
coverage, consumer ownership, normalization report copying and quarantine
classification remain separate obligations.
"""
import re

import legacy_hmac_md5_inner_report as inner
import legacy_hmac_md5_outer_result as outer
import legacy_hmac_md5_return_layout as layout

n, phases, flow, syntax, require, VALUE = inner.n, inner.phases, inner.flow, inner.syntax, inner.require, inner.VALUE
Bits, Pointer, Memory = inner.Bits, inner.Pointer, inner.Memory


def fields(check, base, part):
    pointers = {name: address for name, address in syntax.pointers(check.body, ('%_0',)).items()
                if address[0] == '%_0'}
    start = base + (32 if part == 'inner' else 56)
    found, occupied, sites = {}, set(), set()
    for label, lines in check.graph.items():
        for index, line in enumerate(lines):
            if not set(re.findall(VALUE, line)) & pointers.keys():
                continue
            gep = re.fullmatch(n.pads.descriptors.GEP, line)
            store = re.fullmatch(rf'store (i8|i56|i64|ptr|<2 x i64>) ({VALUE}|\d+|zeroinitializer), ptr ({VALUE}), align \d+(?:, !.*)?', line)
            call = syntax.call(line)
            if gep:
                require(gep[1] in pointers, 'return report output address escapes')
            elif store:
                require(store[3] in pointers and store[2] not in pointers, 'return report output pointer escapes')
                offset = pointers[store[3]][1]
                width = 7 if store[1] == 'i56' else n.bits.width(store[1]) // 8
                overlap = set(range(offset, offset + width)) & set(range(start, start + 24))
                if not overlap:
                    continue
                require(store[1] in ('i64', '<2 x i64>') and offset >= start and offset + width <= start + 24
                        and not overlap & occupied, 'return work fields overlap or are overwritten')
                phases.dominates(check.graph, (check.stop, 0), (label, index))
                found[offset - start] = (store[1], store[2])
                occupied.update(overlap); sites.add((label, index))
            elif call:
                name, args = call
                require(name == 'llvm.memcpy.p0.p0.i64' and len(args) == 4 and args[3] == 'i1 false'
                        and re.fullmatch(r'i64 \d+', args[2]) and syntax.operand(args[0]) in pointers
                        and syntax.operand(args[1]) not in pointers, 'return report output passed to unknown effect')
                offset, width = pointers[syntax.operand(args[0])][1], int(args[2].split()[-1])
                require(offset + width <= start or start + 24 <= offset, 'return work fields replaced by unbound copy')
            else:
                require(False, 'unparsed return report output use: ' + line)
    require(occupied == set(range(start, start + 24)) and len({site[0] for site in sites}) == 1,
            'return work fields missing or split across success blocks')
    return found, sites


def transported(check, fields, mask, backend):
    if isinstance(check, outer.Check):
        check.prepare(mask, backend)
    check.mask, check.selected_backend = mask, backend
    width, count = (8 if backend == 0 else 4), mask.bit_count()
    data = Memory({'result': 56})
    # Phase-specific symbols must not equal earlier accepted inner-state values.
    wanted = (Bits.integer(count, 64), Bits.token((check.result, 'scalar-blocks')),
              Bits.token((check.result, 'vector-blocks')))
    for offset, value in ((0, Pointer('returned-owner')), (8, Bits.token('returned-length')),
                          (16, Bits.integer(width, 64)), (48, Bits.integer(backend, 8)),
                          *((24 + 8 * i, value) for i, value in enumerate(wanted))):
        data.store(Pointer('result', offset), value)
    payload = Bits(tuple(bit for byte in range(56) for bit in data.cells.get(('result', byte), (None,) * 8)))

    def compare(state):
        expected = sum((value.data for value in wanted), ())
        for offset, (dtype, name) in fields.items():
            actual = n.bits.packed(state.value(name, dtype))
            require(actual == Bits(expected[offset * 8:offset * 8 + n.bits.width(dtype)]),
                    'accepted work counter lost return provenance')

    # Vector work is symbolic. Its guard explores both outcomes; every path
    # reaching construction must retain its exact bits, not a convenient count.
    return n.transport.walk(check, check.site, payload, True, None, optional_owner=False,
                            state_type=check.state_type, on_entry=compare)


def validate(fixture, llvm):
    offsets = layout.validate(fixture)
    inner.reports.probes(fixture)
    outer.layouts(fixture)
    n.results.fence.validate_source()
    definitions, aliases = flow.definitions_and_aliases(llvm)
    results = []
    for operation in ('authenticate', 'authenticate_secret', 'verify'):
        signature, body = phases.rows.method(definitions, aliases, operation)[1]
        for part, cls in (('inner', inner.Check), ('outer', outer.Check)):
            check = cls(signature, body, llvm)
            returned, sites = fields(check, offsets[operation], part)
            for backend in (0, 1):
                for mask in range(256):
                    transported(check, returned, mask, backend)
            results.append((check, returned, sites))
    return results
