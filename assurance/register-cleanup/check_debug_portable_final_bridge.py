#!/usr/bin/env python3
"""Retained portable debug final handoff; producer and volatile body stay opaque."""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re

import check_debug_fips202_output as constructor

bulk = constructor.bulk
comparison, model, require = bulk.comparison, bulk.model, bulk.require


@dataclass(frozen=True)
class Case:
    root: str
    kmac: str
    sha3: str
    core: str
    hash_core: str
    enabled: bool


def cases(record):
    for row, kmac, core, _ in comparison.cases(record):
        if row['profile'] != 'debug':
            continue
        paths = [Path(path) for path in row['artifacts']
                 if Path(path).name.startswith('brynja_hash_sha3-') and path.endswith('.ll')]
        require(len(paths) == 1, 'one same-configuration SHA-3 artifact')
        sha3 = (record.parent / paths[0]).read_text()
        hash_core = constructor.supplemental(record, paths[0])
        enabled = row['mode'] == 'accelerated'
        roots = [name for caller in comparison.verifiers(kmac, enabled) for name in bulk.calls(caller)
                 if 'Reader' in name and 'accelerated' not in name
                 and re.search(r'12final_secret(?:17h[0-9a-f]+E"?)?$', name)]
        require(len(roots) == len(set(roots)) == 2, 'both portable final-reader strengths')
        for root in roots:
            yield Case(root, kmac, sha3, core, hash_core, enabled)


def closure(case):
    artifacts = {key: comparison.definitions(getattr(case, key))
                 for key in ('kmac', 'sha3', 'core', 'hash_core')}
    require(case.root in artifacts['kmac'], 'defined actual portable trait bridge')
    root = artifacts['kmac'][case.root]
    header = root.splitlines()[0]
    args = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
    require(header.startswith('define void @') and len(args) == 6
            and args[0] == 'ptr sret([24 x i8]) align 8 %_0'
            and comparison.pointer(args[1]) == '%self.0' and args[2] == 'i1 zeroext %self.1'
            and comparison.pointer(args[3]) == '%output.0'
            and args[4:] == ['i64 %output.1', 'i8 %valid'], 'portable consuming bridge ABI')
    entries = [name for name in bulk.calls(root) if '25squeeze_final_bits_secret' in name]
    require(len(entries) == 1, 'one consuming reader')
    entry = entries[0]
    require(entry in artifacts['sha3'] and 'accelerated' not in entry and ('Cshake128Reader' in entry) == ('Cshake128Reader' in case.root)
            and ('Cshake256Reader' in entry) == ('Cshake256Reader' in case.root), 'same portable identity')
    header = artifacts['sha3'][entry].splitlines()[0]
    args = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
    require(header.startswith('define void @') and len(args) == 4
            and args[0] == 'ptr sret([24 x i8]) align 8 %_0'
            and comparison.pointer(args[1]) == '%0' and args[2] == 'i1 zeroext %1'
            and comparison.pointer(args[3]) == '%output', 'actual consuming reader ABI')
    producers = [name for name in bulk.calls(artifacts['sha3'][entry]) if 'Borrowed' in name and '6secret' in name]
    require(len(producers) == 1 and 'accelerated' not in producers[0], 'one portable borrowed producer')
    producer = producers[0]
    require(producer in artifacts['sha3'], 'defined same-configuration borrowed producer')
    bulk.abi(artifacts['sha3'][producer], 6)
    output_root, output_closure = constructor.closure(constructor.Case(case.sha3, case.hash_core))
    require(output_root in set(bulk.calls(root)), 'actual checked output constructor called')
    intrinsics = {'llvm.memcpy.p0.p0.i64', 'llvm.uadd.with.overflow.i64', 'llvm.umul.with.overflow.i64'}
    selected, owners, excluded, wipes = {}, {}, set(), set()
    pending = [(case.root, 'kmac')]
    while pending:
        name, source = pending.pop()
        if name in intrinsics or name == producer:
            continue
        if '16panic_in_cleanup' in name:
            excluded.add(name)
            continue
        if name not in artifacts[source]:
            matches = [key for key, definitions in artifacts.items() if name in definitions]
            require(len(matches) == 1, 'unique external helper: ' + name)
            source = matches[0]
        body = artifacts[source][name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'no by-value borrowed owner/output')
        if 'secret_memory_volatile23zeroize_region_volatile' in name:
            args = comparison.arguments(body.splitlines()[0], re.search(comparison.SYMBOL, body).end())
            require(body.startswith('define internal void @') and len(args) == 2 and comparison.pointer(args[0]) == '%region.0'
                    and args[1] == 'i64 %region.1', 'actual volatile clear ABI')
            wipes.add(name)
            continue
        if name in selected:
            require(owners[name] == source or (model.parameters(selected[name]) == model.parameters(body)
                    and model.blocks(selected[name]) == model.blocks(body)), 'identical instantiated helper across callers')
            continue
        selected[name], owners[name] = body, source
        pending.extend((callee, source) for callee in bulk.calls(body))
    require(set(output_closure) <= set(selected) and len(selected) == 35 and len(wipes) == 1 and len(excluded) == 1,
            '35-function closure plus one volatile and double-panic boundary')
    return producer, wipes.pop(), output_root, selected


class FinalModel(constructor.ConstructorModel):
    def __init__(self, functions, constants, producer, wipe, output_root, length, valid, active, error, fault):
        super().__init__(functions, constants)
        self.producer, self.wipe, self.output_root = producer, wipe, output_root
        self.length, self.valid, self.active, self.error, self.boundary_fault = length, valid, active, error, fault
        self.exception = (model.Pointer('exception', 7), 19)

    def store(self, ptr, width, value):
        super().store(ptr, width, value)
        if ptr.region == 'result':
            self.events.append(('result', ptr.offset, width, value))

    def run(self, name, args, depth=0):
        if name == self.output_root and self.boundary_fault == 'constructor':
            self.events.append(('constructor-unwind',))
            raise model.Unwind(self.exception)
        if name == self.producer:
            require(len(args) == 6 and self.load(args[1], 8) == model.Pointer('storage')
                    and self.load(model.Pointer(args[1].region, args[1].offset + 8), 1) == self.active
                    and args[2:] == [model.Pointer('output'), self.length, 1, self.valid],
                    'original owner/active/output/length/valid bits, final mode')
            self.events.append(('producer',))
            if self.boundary_fault == 'producer':
                raise model.Unwind(self.exception)
            fields = [(0, 8, 2), (8, 1, self.error)] if self.error is not None else [
                (0, 8, int(self.length != 0)), (8, 8, model.Pointer('output')), (16, 8, self.length)]
            for offset, width, value in fields:
                self.store(model.Pointer(args[0].region, args[0].offset + offset), width, value)
            return None
        if name == self.wipe:
            require(len(args) == 2 and isinstance(args[0], model.Pointer) and args[0].region == 'storage'
                    and type(args[1]) is int, 'original owned region clear request')
            self.address(args[0], args[1], access=False)
            self.events.append(('wipe', args[0].offset, args[1]))
            return None
        if name == 'llvm.memcpy.p0.p0.i64':
            require(len(args) == 4 and args[2] in (24, 32) and args[3] == 0, 'whole nonvolatile descriptor move')
            destination, source, length, _ = args
            self.address(source, length)
            self.address(destination, length)
            require(source.region != destination.region, 'nonoverlapping metadata copy')
            fields = [(ptr.offset - source.offset, width, value) for ptr, (width, value) in self.memory.items()
                      if ptr.region == source.region and source.offset <= ptr.offset < source.offset + length]
            require(all(offset + width <= length for offset, width, _ in fields), 'whole descriptor fields')
            for offset, width, value in fields:
                self.store(model.Pointer(destination.region, destination.offset + offset), width, value)
            return None
        return super().run(name, args, depth)


def regions():
    # Independent source-owned layout: counters, state, rate buffer, domains,
    # and permutation scratch. No payload loads or direct state writes allowed.
    # Both rate instantiations own MAX_RATE=168 buffers, not rate-sized arrays.
    return [(48, 200), (248, 168), (0, 16), (16, 16), (32, 16),
            (1036, 1), (1037, 3), (1032, 4), (416, 168), (584, 168),
            (752, 40), (792, 40), (832, 200)]


def inspect(case, thorough=True):
    producer, wipe, output_root, selected = closure(case)
    functions = {name: (model.parameters(body), model.blocks(body)) for name, body in selected.items()}
    constants = '\n'.join(dict.fromkeys(line for text in (case.kmac, case.sha3, case.core, case.hash_core)
                                      for line in text.splitlines() if line.startswith(('@anon.', '@alloc_'))))
    rate = 168 if 'Cshake128Reader' in case.root else 136
    cleanup = [('wipe', *region) for region in regions()]
    lengths = (0, 1, rate - 1, rate, rate + 1, 4096, 1 << 61, (1 << 61) + 1) if thorough else (0, 1, 1 << 61, (1 << 61) + 1)
    valids = (0, 1, 7, 8, 9, 255) if thorough else (0, 8, 9)
    count, visited = 0, set()
    for length in lengths:
        for valid in valids:
            shape = (valid == 0 if length == 0 else 1 <= valid <= 8)
            admitted = shape and (0 if length == 0 else (length - 1) * 8 + valid) <= model.MASK
            outcomes = [(None, None), (None, 'constructor')]
            if admitted:
                outcomes += [(None, 'producer')] + [(error, None) for error in range(5)]
            for active in (0, 1):
                for error, fault in outcomes:
                    machine = FinalModel(functions, constants, producer, wipe, output_root, length, valid, active, error, fault)
                    result = machine.allocate('result', 24)
                    storage = machine.allocate('storage', 1040, payload=True)
                    output = machine.allocate('output', length, payload=True)
                    try:
                        require(machine.run(case.root, [result, storage, active, output, length, valid]) is None, 'void handoff')
                    except model.Unwind as failure:
                        require(fault is not None and failure.value == machine.exception, 'unchanged boundary exception')
                    else:
                        require(fault is None, 'boundary unwind cannot be swallowed')
                    converted = (0, 3, 4, 4, 5)[error] + (12 if case.enabled else 0) if error is not None else None
                    if fault == 'constructor':
                        expected = [('constructor-unwind',)] + cleanup
                    elif not admitted:
                        expected = [('result', 8, 1, 18 if case.enabled else 6), ('result', 0, 8, 2)] + cleanup
                    else:
                        expected = [('producer',)] + cleanup
                        if fault is None:
                            fields = [(8, 1, converted), (0, 8, 2)] if error is not None else [
                                (0, 8, int(length != 0)), (8, 8, output), (16, 8, length)]
                            expected += [('result', *field) for field in fields]
                    require(machine.events == expected, 'exact handoff/result and thirteen once-only owned clears before return/resume')
                    visited.update(machine.visited)
                    count += 1
    expected = constructor.covered_blocks(functions)
    for name, (_, graph) in functions.items():
        for label, lines in graph.items():
            if any('16panic_in_cleanup' in line for line in lines) or (
                    'secret_memory18clear_owned_region' in name and any(line.startswith('store i8 0,') for line in lines)):
                expected.discard((name, label))
    require(visited == expected, 'all selected constructor/final-handoff/cleanup/error/unwind blocks visited')
    return count, visited, selected


def main(record):
    before = comparison.capture.sources()
    results = [inspect(case) for case in cases(record)]
    require(len(results) == 16 and all(count == 408 for count, _, _ in results)
            and before == comparison.capture.sources(), 'unchanged complete debug portable matrix')
    print('Portable debug final bridges: ' + repr([(count, len(selected)) for count, _, selected in results]) + ' PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Producer/volatile bodies opaque; synthetic boundary unwind, no whole-verifier/register/spill/native proof; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
