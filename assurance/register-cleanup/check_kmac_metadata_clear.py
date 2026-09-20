#!/usr/bin/env python3
"""Retained scoped KMAC metadata clearing requests and core forwarding, not erasure proof."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_verify_comparisons as comparison
import debug_write_model as model

require = comparison.require


def one(definitions, predicate, label):
    matches = [(name, body) for name, body in definitions.items() if predicate(name)]
    require(len(matches) == 1, 'unique ' + label)
    return matches[0]


def select(kmac, core):
    definitions = comparison.definitions(kmac)
    scoped = {name: body for name, body in definitions.items()
              if 'hardened_in_place' in name and 'core_state' in name and 'drop_in_place' not in name}
    names, functions = {}, {}
    for role, predicate in (
            ('WIPE', lambda name: '8Metadata4wipe' in name),
            ('DROP', lambda name: 'Metadata' in name and '4drop' in name),
            ('GUARD', lambda name: 'Guard' in name and '4drop' in name)):
        names[role], functions[role] = one(scoped, predicate, 'scoped metadata ' + role)
    core_defs = comparison.definitions(core)
    names['CLEAR'], functions['CLEAR'] = one(core_defs, lambda name: '18clear_owned_region' in name, 'core clearing wrapper')
    names['ZERO'], _ = one(core_defs, lambda name: 'secret_memory_volatile23zeroize_region_volatile' in name, 'volatile clearing callee')
    empties = {match[1] for match in re.finditer(comparison.SYMBOL, functions['CLEAR']) if '8is_empty' in match[1]}
    require(len(empties) <= 1, 'single emptiness helper')
    if empties:
        names['EMPTY'] = empties.pop()
        require(names['EMPTY'] in core_defs, 'defined emptiness helper')
        functions['EMPTY'] = core_defs[names['EMPTY']]
    return functions, names


def bridge(functions, names, compiler, profile):
    """Closed wrapper CFG: empty skips stores; nonempty forwards unchanged slice."""
    for role, result in (('CLEAR', 'i8'), ('EMPTY', 'i1')):
        if role not in functions:
            continue
        header = functions[role].splitlines()[0]
        symbol = re.search(comparison.SYMBOL, header)
        require(header.startswith('define ') and symbol is not None
                and symbol[1] == names[role] and header[:symbol.start()].endswith(result + ' '),
                'bound clearing wrapper identity and result ABI')
    function = functions['CLEAR']
    require(model.parameters(function) == ['%region.0', '%region.1'], 'clearing wrapper parameter order')
    graph = model.blocks(function)
    for block, lines in graph.items():
        for index, line in enumerate(lines):
            if 'call ' not in line:
                continue
            symbol = re.search(comparison.SYMBOL, line)
            require(symbol is not None, 'direct clearing wrapper call')
            role = next((key for key in ('EMPTY', 'ZERO') if names.get(key) == symbol[1]), None)
            require(role is not None, 'only bound emptiness/volatile helper calls')
            args = comparison.arguments(line, symbol.end())
            require(len(args) == 2 and comparison.pointer(args[0]) == '%region.0'
                    and re.fullmatch(r'i64(?: noundef)? %region\.1', args[1]), 'unchanged clearing slice arguments')
            prefix = line[:symbol.start()]
            expected = ('%_2 = call zeroext i1 ' if role == 'EMPTY' else
                        'tail call fastcc void ' if profile == 'release' else 'call void ')
            require(prefix == expected, 'clearing helper return/call ABI')
            exact = prefix + '@' + symbol[1] + '(' + ', '.join(args) + ')'
            require(re.fullmatch(re.escape(exact) + r'(?: #\d+)?', line), 'single complete wrapper call')
            lines[index] = ('%_2 = call EMPTY' if role == 'EMPTY' else 'call ZERO')
    require(compiler in ('1.90.0', '1.98.1'), 'reviewed clearing result representation')
    success = '4' if compiler == '1.90.0' else '-1'
    if profile == 'debug':
        expected = {
            'start': ['%region.dbg.spill = alloca [16 x i8], align 8', '%_0 = alloca [1 x i8], align 1',
                      'store ptr %region.0, ptr %region.dbg.spill, align 8',
                      '%0 = getelementptr inbounds i8, ptr %region.dbg.spill, i64 8',
                      'store i64 %region.1, ptr %0, align 8', '%_2 = call EMPTY', 'br i1 %_2, label %bb2, label %bb3'],
            'bb3': ['call ZERO', f'store i8 {success}, ptr %_0, align 1', 'br label %bb5'],
            'bb2': ['store i8 0, ptr %_0, align 1', 'br label %bb5'],
            'bb5': ['%1 = load i8, ptr %_0, align 1', 'ret i8 %1'],
        }
        require('EMPTY' in functions and model.parameters(functions['EMPTY']) == ['%self.0', '%self.1'], 'bound debug emptiness parameters')
        require(model.blocks(functions['EMPTY']) == {'start': [
            '%self.dbg.spill = alloca [16 x i8], align 8', 'store ptr %self.0, ptr %self.dbg.spill, align 8',
            '%0 = getelementptr inbounds i8, ptr %self.dbg.spill, i64 8', 'store i64 %self.1, ptr %0, align 8',
            '%_0 = icmp eq i64 %self.1, 0', 'ret i1 %_0']}, 'descriptor-only emptiness predicate')
    else:
        require(profile == 'release' and 'EMPTY' not in functions, 'optimized inline emptiness check')
        expected = {
            'start': ['%0 = icmp eq i64 %region.1, 0', 'br i1 %0, label %bb4, label %bb2'],
            'bb2': ['call ZERO', 'br label %bb4'],
            'bb4': [f'%_0.sroa.0.0 = phi i8 [ {success}, %bb2 ], [ 0, %start ]', 'ret i8 %_0.sroa.0.0'],
        }
    require(graph == expected, 'closed clearing-wrapper geometry/control flow')


class MetadataModel(model.Model):
    def __init__(self, functions, names, base):
        super().__init__(functions, '', '')
        self.clear = names['CLEAR']
        self.base = base
        self.calls = []

    def run(self, name, args, depth=0):
        if name == self.clear:
            require(len(args) == 2 and type(args[1]) is int, 'clearing slice ABI')
            pointer, width = args
            self.address(pointer, width, access=False)
            require(pointer.region == 'metadata' and self.base <= pointer.offset
                    and pointer.offset + width <= self.base + 66, 'clear only original metadata storage')
            self.calls.append((pointer.offset - self.base, width))
            return 0  # Caller discards this byte; no erasure outcome inferred.
        return super().run(name, args, depth)


def inspect(functions, names, compiler, profile):
    bridge(functions, names, compiler, profile)
    selected = {}
    for role in ('WIPE', 'DROP', 'GUARD'):
        function = functions[role]
        header = function.splitlines()[0]
        require(header.startswith('define void @') and model.parameters(function) == ['%self'], 'borrowed void metadata cleanup ABI')
        symbol = re.search(comparison.SYMBOL, header)
        require(symbol is not None and symbol[1] == names[role], 'bound metadata cleanup identity')
        graph = model.blocks(function)
        require(set(graph) == {'start'}, 'linear metadata cleanup body')
        selected[names[role]] = (['%self'], {'start': [line.replace('tail call ', 'call ', 1) for line in graph['start']]})
    for base in (0, 17):
        for role in ('WIPE', 'DROP', 'GUARD'):
            machine = MetadataModel(selected, names, base)
            machine.allocate('metadata', base + 66 + 9, payload=True)
            owner = model.Pointer('metadata', base)
            guard = machine.allocate('guard', 8)
            machine.store(guard, 8, owner)
            argument = guard if role == 'GUARD' else owner
            require(machine.run(names[role], [argument]) is None, 'no metadata cleanup return payload')
            require(machine.calls == [(64, 1), (0, 64), (65, 1)], 'three complete ordered metadata regions')
            require(machine.load(guard, 8) == owner, 'borrowed guard descriptor preserved')
    return 6


def cases(record):
    for row, kmac, core, _ in comparison.cases(record):
        functions, names = select(kmac, core)
        yield functions, names, row['compiler'].splitlines()[0].split()[1], row['profile']


def main(record):
    before = comparison.capture.sources()
    builds = cases_checked = 0
    for functions, names, compiler, profile in cases(record):
        cases_checked += inspect(functions, names, compiler, profile)
        builds += 1
    require(builds == 16 and before == comparison.capture.sources(), 'complete unchanged metadata cleanup matrix')
    print(f'KMAC metadata cleanup: {builds * 3} definitions, {cases_checked} modeled calls and {builds} core forwarding contracts PASS')
    print('All 1/64/1-byte regions requested in order; no payload loads; core wrapper forwards the original nonempty slice')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Opaque volatile-callee boundary; not destructor reachability, new binary execution, whole-call residue or native-platform qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
