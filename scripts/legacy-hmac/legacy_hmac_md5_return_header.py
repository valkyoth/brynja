"""Bind return report width/backend to actual immutable selection values.

Independent error constructors establish each compiler's Result error niche. Error
writes are not success fields. This does not assert that all returns select
the correct variant or bind returned output-owner lifetimes.
"""
import re

import legacy_hmac_md5_return_writes as output

r = output.returned
inner, layout, require, Bits = r.inner, r.layout, r.require, r.Bits


def probes(fixture):
    offsets = layout.validate(fixture)
    result = {}
    for operation, base in offsets.items():
        name = {'authenticate': 'public_error', 'authenticate_secret': 'secret_error', 'verify': 'verify_error'}[operation]
        memory = layout.probe(fixture, name, base + 88, {}, {'%error': Bits.token('error', 8)})
        niches = [offset for offset in (0, base + 80) if layout.read(memory, offset, 1) == Bits.integer(2, 8)]
        require(len(niches) == 1 and layout.read(memory, 1 if niches[0] == 0 else 0, 1)
                == Bits.token('error', 8), 'MD5 return error niche changed')
        result[operation] = (base, niches[0])
    return result


def fields(check, base, niche):
    occupied, found, blocks = set(), [], set()
    expected = set(range(base, base + 8)) | {base + 80}
    for site, offset, size, dtype, value in output.writes(check.body):
        touched = set(range(offset, offset + size)) & expected
        if not touched:
            continue
        if offset == niche and dtype == 'i8' and value == '2':
            continue  # ABI-bound Err niche, not an accepted backend.
        require(touched == set(range(offset, offset + size)) and not occupied & touched
                and dtype in ('i8', 'i56', 'i64'), 'return report header missing/overwritten')
        r.phases.dominates(check.graph, (check.stop, -1), site)
        occupied.update(touched); blocks.add(site[0]); found.append((offset - base, dtype, value, site))
    require(occupied == expected and len(blocks) == 1, 'return report header incomplete or split')
    return found


def narrowed(source, expression):
    require(source.number() is not None and 0 <= source.number() <
            (128 if ' nsw ' in expression else 256), 'return width narrowing can wrap or poison')
    return source.resize(8)


def transported(check, fields, mask, backend):
    width = 8 if backend == 0 else 4

    def compare(state):
        for offset, dtype, name, site in fields:
            if dtype == 'i56':
                require(name == '0', 'return width upper bytes changed')
                actual = Bits.integer(0, 56)
            else:
                definition = check.defs.get(name)
                expression = definition[1].split(' = ', 1)[1] if definition else ''
                narrow = re.fullmatch(rf'trunc(?: nuw)?(?: nsw)? i64 ({r.VALUE}) to i8', expression)
                select = re.fullmatch(rf'select i1 {r.VALUE}, (i8|i64) \d+, \1 \d+', expression)
                if narrow or select:
                    r.phases.dominates(check.graph, definition[0], site)
                    if narrow:
                        actual = narrowed(state.value(narrow[1], 'i64'), expression)
                    else:
                        actual = state.expression(expression)
                else:
                    actual = state.value(name, dtype)
            expected = Bits.integer(backend, 8) if offset == 80 else Bits.integer(width, 64)
            start = 0 if offset == 80 else offset * 8
            require(actual == Bits(expected.data[start:start + len(actual.data)]),
                    'returned header lost selected backend/width')

    check.run_report(mask, backend, on_entry=compare)


def validate(fixture, llvm):
    offsets = probes(fixture)
    definitions, aliases = r.flow.definitions_and_aliases(llvm)
    checks = []
    for operation, (base, niche) in offsets.items():
        check = inner.Check(*r.phases.rows.method(definitions, aliases, operation)[1], llvm)
        found = fields(check, base, niche)
        for backend in (0, 1):
            for mask in range(256):
                transported(check, found, mask, backend)
        checks.append((check, found))
    return checks
