#!/usr/bin/env python3
"""Retained debug final-output shape/length constructor and its actual helpers."""
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

import check_debug_kmac_bulk_bridge as bulk
import check_fips202_output_constructor as optimized

comparison, model, require = bulk.comparison, bulk.model, bulk.require

# Supplemental, same-capture files checked against the protected archive. They
# were present in that archive, but are not part of the original 240-file index.
# These are diagnostic artifact pins, not new release-gate inputs.
HASH_CORE = {
    '1.90.0-x86_64-unknown-linux-gnu-debug-portable': ('78081ceeda2053ca', 'a307f126940718f7ff7b79579e6e1a7198b1a06f95bec80a727adc1233c7f152'),
    '1.90.0-x86_64-unknown-linux-gnu-debug-accelerated': ('c5dd363be618cbcf', 'c5d4e5fe71550a7e57101bd14bef9ec00f05f0ce746d1ae4d77c3b90fe36e695'),
    '1.90.0-aarch64-unknown-linux-musl-debug-portable': ('24596ae116498a72', 'cfe74ace629deae020f56048ec1bbcc12a58f9218bb3bd34b319e13c726b72f7'),
    '1.90.0-aarch64-unknown-linux-musl-debug-accelerated': ('b5f95bc8f3d6e3c6', '5e837ded08b9972122cfbb7bd96001bb92d1572710568344467e332af957ab0b'),
    '1.98.1-x86_64-unknown-linux-gnu-debug-portable': ('869c38e554f55e59', 'cc8060c2bef9d287140e1aa7d3c06c57b176a9d0e22a5f7b362de0bf35d7008c'),
    '1.98.1-x86_64-unknown-linux-gnu-debug-accelerated': ('eef3dc3e7f3a7694', 'a571a232a135adaec908199f36536db0eda09b75279cadd4371aa81d19c8b992'),
    '1.98.1-aarch64-unknown-linux-musl-debug-portable': ('d57a378edc5f7ef0', '2d8f354bd7e96168dc5f8f1bef0cb542179d889421afa0141b94cb8b6b7fa943'),
    '1.98.1-aarch64-unknown-linux-musl-debug-accelerated': ('fc91c393756c1c06', '37aee34eddeeb91a311156851812553f8ed23d98ef4d5758d1db0386d4c6bbb1'),
}


@dataclass(frozen=True)
class Case:
    sha3: str
    hash_core: str


def supplemental(record, sha3_path):
    config = sha3_path.parts[0]
    require(config in HASH_CORE, 'reviewed supplemental debug configuration')
    suffix, digest = HASH_CORE[config]
    relative = sha3_path.parent / ('brynja_hash_core-' + suffix + '.ll')
    path = record.parent / relative
    require(path.resolve().is_relative_to(record.parent.resolve()) and not path.is_symlink(),
            'supplemental file stays in this capture')
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == digest, 'exact archived supplemental hash-core bytes')
    return raw.decode()


def cases(record):
    for row, _, _, _ in comparison.cases(record):
        if row['profile'] != 'debug':
            continue
        paths = [Path(path) for path in row['artifacts']
                 if Path(path).name.startswith('brynja_hash_sha3-') and path.endswith('.ll')]
        require(len(paths) == 1, 'one same-configuration SHA-3 LLVM artifact')
        yield Case((record.parent / paths[0]).read_text(), supplemental(record, paths[0]))


def closure(case):
    artifacts = {'sha3': comparison.definitions(case.sha3), 'hash_core': comparison.definitions(case.hash_core)}
    roots = [name for name in artifacts['sha3'] if 'Fips202Output3new' in name]
    require(len(roots) == 1, 'one defined final-output constructor')
    root = roots[0]
    header = artifacts['sha3'][root].splitlines()[0]
    args = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
    require(header.startswith('define void @') and len(args) == 4
            and args[0] == 'ptr sret([32 x i8]) align 8 %_0'
            and comparison.pointer(args[1]) == '%bytes.0'
            and args[2:] == ['i64 %bytes.1', 'i8 %valid_bits_in_last_byte'], 'borrowed constructor ABI')
    selected, owners, pending = {}, {}, [(root, 'sha3')]
    intrinsics = {'llvm.memcpy.p0.p0.i64', 'llvm.uadd.with.overflow.i64', 'llvm.umul.with.overflow.i64'}
    while pending:
        name, source = pending.pop()
        if name in intrinsics:
            continue
        if name not in artifacts[source]:
            matches = [key for key, definitions in artifacts.items() if name in definitions]
            require(len(matches) == 1, 'unambiguous actual external constructor helper: ' + name)
            source = matches[0]
        if name in selected:
            require(owners[name] == source, 'same-artifact constructor helper identity')
            continue
        body = artifacts[source][name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'no by-value borrowed output')
        selected[name], owners[name] = body, source
        pending.extend((callee, source) for callee in bulk.calls(body))
    require(any(source == 'hash_core' for source in owners.values()), 'actual separately emitted range helper included')
    require(len(selected) == 19, 'complete nineteen-function constructor closure')
    return root, selected


class ConstructorModel(model.Model):
    def __init__(self, functions, globals_text):
        super().__init__(functions, globals_text, '')
        self.result_writes = []
        for line in globals_text.splitlines():
            found = re.fullmatch(r'(@[-.$\w]+) = private unnamed_addr constant \[3 x i8\] c"((?:\\[0-9A-Fa-f]{2}){3})", align 1', line)
            if found:
                self.allocate(found[1], 3)
                for offset, byte in enumerate(re.findall(r'\\([0-9A-Fa-f]{2})', found[2])):
                    self.memory[model.Pointer(found[1], offset)] = (1, int(byte, 16))

    def store(self, ptr, width, value):
        super().store(ptr, width, value)
        if ptr.region == 'result':
            self.result_writes.append((ptr.offset, width, value))

    def run(self, name, args, depth=0):
        if name == 'llvm.umul.with.overflow.i64':
            require(len(args) == 2 and all(type(value) is int and 0 <= value <= model.MASK for value in args),
                    'unsigned checked multiplication operands')
            value = args[0] * args[1]
            return value & model.MASK, int(value > model.MASK)
        if name == 'llvm.memcpy.p0.p0.i64':
            require(len(args) == 4 and args[2:] == [32, 0], 'complete nonvolatile output descriptor move')
            destination, source = args[:2]
            self.address(source, 32)
            self.address(destination, 32)
            require(source.region != destination.region, 'nonoverlapping descriptor move')
            values = [(ptr.offset - source.offset, width, value) for ptr, (width, value) in self.memory.items()
                      if ptr.region == source.region and source.offset <= ptr.offset < source.offset + 32]
            require(all(offset + width <= 32 for offset, width, _ in values), 'complete typed descriptor fields')
            for offset, width, value in values:
                self.store(model.Pointer(destination.region, destination.offset + offset), width, value)
            return None
        return super().run(name, args, depth)


def covered_blocks(functions):
    expected_blocks = set()
    for name, (_, graph) in functions.items():
        reachable, pending = set(), ['start']
        while pending:
            label = pending.pop()
            require(label in graph, 'defined helper successor')
            if label in reachable:
                continue
            reachable.add(label)
            pending.extend(target for line in graph[label] for target in re.findall(r'label %([-.$\w]+)', line))
        # Fixed, unexhausted inclusive 1..=8 bounds cannot take the generic
        # Excluded/Unbounded arms. Option::or also contains disconnected compiler
        # unwind scaffolding, excluded by the actual successor walk above.
        excluded = {'bb1'} if '9end_bound' in name else (
            {'bb3', 'bb4', 'bb10', 'bb11'} if 'RangeBounds' in name and '8contains' in name else set())
        require(excluded <= set(graph), 'known fixed-range helper exclusions')
        expected_blocks.update((name, label) for label in reachable - excluded if graph[label] != ['unreachable'])
    return expected_blocks


def inspect(case, thorough=True):
    root, selected = closure(case)
    functions = {name: (model.parameters(body), model.blocks(body)) for name, body in selected.items()}
    constants = '\n'.join(dict.fromkeys(line for line in (case.sha3 + '\n' + case.hash_core).splitlines()
                                       if line.startswith(('@anon.', '@alloc_'))))
    visited, count = set(), 0
    valids = optimized.VALIDS if thorough else optimized.VALIDS[:6]
    for length in optimized.LENGTHS:
        for valid in valids:
            machine = ConstructorModel(functions, constants)
            result = machine.allocate('result', 32)
            output = machine.allocate('output', length, payload=True)
            require(machine.run(root, [result, output, length, valid]) is None, 'void constructor result')
            shape = (valid == 0 if length == 0 else 1 <= valid <= 8)
            bits = 0 if length == 0 else (length - 1) * 8 + valid
            if not shape or bits > model.MASK:
                expected = [(8, 1, 0 if not shape else 2), (0, 8, 0)]
            else:
                expected = [(0, 8, output), (8, 8, length), (16, 8, bits), (24, 1, valid)]
            require(machine.result_writes == expected, 'exact shape/overflow error or original output/bit-length descriptor')
            require(not machine.events, 'no payload copy or mutable owner effects')
            visited.update(machine.visited)
            count += 1
    require(visited == covered_blocks(functions), 'all constructor and fixed-inclusive helper paths covered')
    return count, len(selected)


def main(record):
    before = comparison.capture.sources()
    results = [inspect(case) for case in cases(record)]
    require(results == [(2560, 19)] * 8 and before == comparison.capture.sources(), 'unchanged complete debug matrix')
    print('Debug final-output constructor: ' + repr(results) + ' modeled cases/helper counts PASS')
    print('Supplemental hash-core pins: ' + json.dumps(HASH_CORE, sort_keys=True))
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Scalar descriptor modeling only; no whole final-reader, producer, payload cleanup, spill or native-platform proof; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
