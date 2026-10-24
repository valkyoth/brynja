"""Interpret independent straight-line report/result constructor ABI probes."""
import re
from types import SimpleNamespace

import legacy_hmac_md5_inner_report as inner

n, phases, flow, syntax, require, VALUE = inner.n, inner.phases, inner.flow, inner.syntax, inner.require, inner.VALUE
Bits, Pointer, Memory = inner.Bits, inner.Pointer, inner.Memory


def probe(fixture, name, extent, regions, values):
    definitions, aliases = flow.definitions_and_aliases(fixture)
    body = n.pads.descriptors.admission.probe(definitions, aliases, name)
    graph, allocs = flow.blocks(body), phases.allocations(body)
    require(len(graph) == 1, 'return ABI probe gained control flow')
    memory = Memory({**allocs, '%_0': extent, **regions})
    for root, size in regions.items():
        memory.store(Pointer(root), Bits.token(root, size * 8))
    check = SimpleNamespace(allocs=allocs, workspace='%unused', output='%_0', scope=None, defs={}, graph=graph)
    state = n.transport.State(check, (next(iter(graph)), 0), memory)
    state.values.update({name: Pointer(name) for name in ('%_0', *regions)})
    state.values.update(values)
    live = {'%_0', *regions}
    lines = next(iter(graph.values()))
    require(lines[-1] == 'ret void', 'return ABI probe lacks return')
    for line in lines[:-1]:
        definition = re.fullmatch(rf'({VALUE}) = (.*)', line)
        store = re.fullmatch(rf'store (ptr|i8|i64) ({VALUE}|\d+), ptr ({VALUE}), align \d+', line)
        call = syntax.call(line)
        if definition and ' = alloca ' in line:
            require(definition[1] in allocs, 'unparsed return probe allocation')
        elif call:
            symbol, args = call
            if symbol in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0'):
                root = syntax.operand(args[-1])
                require(root in allocs and len(args) in (1, 2) and
                        (len(args) == 1 or args[0] == 'i64 ' + str(allocs[root])), 'ABI probe lifetime changed')
                require((root in live) == (symbol == 'llvm.lifetime.end.p0'), 'ABI probe lifetime repeated')
                live.add(root) if symbol == 'llvm.lifetime.start.p0' else live.remove(root)
                memory.invalidate(root)
            else:
                require(symbol == 'llvm.memcpy.p0.p0.i64' and len(args) == 4 and args[3] == 'i1 false'
                        and re.fullmatch(r'i64 \d+', args[2]), 'unreviewed return probe effect')
                dest, source = (state.address(syntax.operand(arg)) for arg in args[:2])
                count = int(args[2].split()[-1])
                require(dest.root in live - regions.keys() and source.root in live, 'ABI probe copies expired/input storage')
                memory.bounds(dest, count); memory.bounds(source, count)
                require(dest.root != source.root or dest.offset + count <= source.offset or
                        source.offset + count <= dest.offset, 'ABI probe copy overlaps')
                data = Bits(tuple(bit for byte in range(source.offset, source.offset + count)
                                  for bit in memory.cells.get((source.root, byte), (None,) * 8)))
                memory.store(dest, data)
        elif definition:
            state.values[definition[1]] = state.expression(definition[2])
        elif store:
            dest = state.address(store[3])
            require(dest.root in live - regions.keys(), 'ABI probe overwrites input/expired storage')
            memory.store(dest, state.value(store[2], store[1]))
        else:
            require(False, 'unparsed return ABI probe: ' + line)
    return memory


def read(memory, offset, size):
    return Bits(tuple(bit for byte in range(offset, offset + size)
                      for bit in memory.cells.get(('%_0', byte), (None,) * 8)))


def validate(fixture):
    work = {'%normalization': 24, '%inner': 24, '%outer': 24}
    memory = probe(fixture, 'hmac_report', 88, work,
                   {'%width': Bits.token('width'), '%backend': Bits.token('backend', 1)})
    require(read(memory, 0, 8) == Bits.token('width') and
            read(memory, 80, 1) == Bits.token('backend', 1).resize(8), 'HMAC report header layout changed')
    for offset, name in ((8, '%normalization'), (32, '%inner'), (56, '%outer')):
        require(read(memory, offset, 24) == Bits.token(name, 192), 'HMAC work report field layout changed')
    offsets = {}
    for operation, name, prefix in (('authenticate', 'public_success', 24),
                                    ('authenticate_secret', 'secret_success', 32),
                                    ('verify', 'verify_success', 8)):
        regions = {'%report': 88, **({'%tags': prefix} if prefix != 8 else {})}
        memory = probe(fixture, name, prefix + 88, regions, {'%decision': Bits.token('decision', 8)})
        require(read(memory, prefix, 88) == Bits.token('%report', 704), 'result report offset/extent changed')
        offsets[operation] = prefix
    return offsets
