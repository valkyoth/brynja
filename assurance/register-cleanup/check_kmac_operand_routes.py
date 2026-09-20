#!/usr/bin/env python3
"""Retained optimized KMAC operand routing, under reader-output contracts."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_metadata_transfer as transfer

early = transfer.early
comparison = transfer.comparison
guard = transfer.guard
require = transfer.require
SSA = transfer.SSA


class Trace:
    def __init__(self, function, names, defined):
        self.graph, self.edges, _, self.comparisons, self.origin, self.owner, _ = early.optimized.inventory(function, names, defined)
        self.definitions = {}
        self.used = set()
        self.copies = set()
        for label, lines in self.graph.items():
            for line in lines:
                match = re.match('(' + SSA + r') = (.+)', line)
                if match:
                    self.definitions[match[1]] = label, match[2]

    def match(self, value, pattern):
        require(value in self.definitions, 'defined comparison operand: ' + value)
        self.used.add(value)
        match = re.fullmatch(pattern, self.definitions[value][1])
        require(match is not None, 'reviewed operand definition: ' + value)
        return match

    def phi(self, value, kind):
        text = self.match(value, 'phi ' + kind + r' (.+)')[1]
        entries = re.findall(r'\[ (' + SSA + r'|\d+), %(' + guard.LABEL + r') \]', text)
        require(len(entries) == 2 and ', '.join(f'[ {v}, %{b} ]' for v, b in entries) == text,
                'exact two-input operand recurrence')
        label = self.definitions[value][0]
        incoming = {source for source in self.graph if label in self.edges[source][0]}
        require({b for _, b in entries} == incoming, 'phi values correspond to actual incoming edges')
        return entries

    def candidate(self, value, kind, offset):
        pointer = self.match(value, 'load ' + kind + r', ptr (' + SSA + r'), align 8')[1]
        require(self.origin(pointer) == ('%candidate', offset), 'candidate pointer/length comes from the input descriptor')
        if pointer != '%candidate':
            self.match(pointer, r'getelementptr inbounds nuw i8, ptr %candidate, i64 ' + str(offset))

    def output(self, value):
        pointer = self.match(value, r'load ptr, ptr (' + SSA + r'), align 8')[1]
        slot, offset = self.origin(pointer)
        require(offset == 8, 'secret-output pointer field')
        self.match(pointer, r'getelementptr inbounds nuw i8, ptr ' + re.escape(slot) + r', i64 8')
        self.match(slot, r'alloca \[24 x i8\], align 8')
        return slot

    def difference(self, value, call_label):
        gep = self.match(value, r'getelementptr inbounds nuw i8, ptr (' + SSA + r'), i64 (65|' + SSA + ')')
        require(gep[1] == self.owner, 'difference belongs to extracted metadata owner')
        if gep[2] == '65':
            return
        index = gep[2]
        entries = self.phi(index, 'i64')
        increments = [(v, b) for v, b in entries if v != '65']
        require(len(increments) == 1 and increments[0][1] == call_label, 'single-byte difference loop feedback')
        increment = increments[0][0]
        self.match(increment, r'add nuw nsw i64 ' + re.escape(index) + r', 1')
        header = self.definitions[index][0]
        require(self.definitions[increment][0] == call_label and self.edges[call_label][0][0] == header,
                'successful accumulation advances the difference loop')
        branch = re.fullmatch(r'br i1 (' + SSA + r'), label %(' + guard.LABEL + r'), label %(' + guard.LABEL + ')', self.graph[header][-1])
        require(branch is not None and branch[3] == call_label and branch[2] != call_label, 'difference loop exits at its limit')
        self.match(branch[1], r'icmp eq i64 ' + re.escape(index) + r', 66')


def output_producer(trace, slot, metadata, requested, tail, callees):
    # The pointer field is assembled from byte 8 plus the following seven bytes
    # of a 24-byte Result/secret-output descriptor. Follow both writes, not just
    # a matching call somewhere in the verifier.
    copies, bytes_at_eight = [], []
    for label, lines in trace.graph.items():
        for index, line in enumerate(lines):
            if '@llvm.memcpy.p0.p0.i64(' in line:
                _, args = guard.call(line)
                if trace.origin(comparison.pointer(args[0])) == (slot, 9):
                    trace.copies.add(line)
                    require(args[2:] == ['i64 15', 'i1 false'], 'complete secret-output descriptor tail')
                    source, offset = trace.origin(comparison.pointer(args[1]))
                    if offset == 0:
                        trace.match(source, r'alloca \[15 x i8\], align 4')
                        staging = []
                        for block in trace.graph.values():
                            for staged in block:
                                if '@llvm.memcpy.p0.p0.i64(' not in staged:
                                    continue
                                _, staged_args = guard.call(staged)
                                if comparison.pointer(staged_args[0]) == source:
                                    trace.copies.add(staged)
                                    require(staged_args[2:] == ['i64 15', 'i1 false'], 'complete staging descriptor copy')
                                    staging.append(trace.origin(comparison.pointer(staged_args[1])))
                        require(len(staging) == 1, 'unique bounded descriptor staging copy')
                        source, offset = staging[0]
                    require(offset == 9, 'matching returned descriptor field')
                    copies.append((label, source))
            store = re.fullmatch(r'store i8 (' + SSA + r'), ptr (' + SSA + r'), align 8', line)
            if store and trace.origin(store[2]) == (slot, 8):
                pointer = trace.match(store[1], r'load i8, ptr (' + SSA + r'), align 8')[1]
                source, offset = trace.origin(pointer)
                require(offset == 8, 'first pointer byte comes from the returned descriptor')
                bytes_at_eight.append((label, source))
    require(len(copies) == len(bytes_at_eight) == 1 and copies == bytes_at_eight,
            'one matching descriptor-copy/first-byte pair')
    result = copies[0][1]
    trace.match(result, r'alloca \[24 x i8\], align 8')
    producers = []
    for label, lines in trace.graph.items():
        for line in lines:
            if not line.startswith('invoke void @'):
                continue
            name, args = guard.call(line)
            if args[0].endswith(' ' + result):
                expected = ('12final_secret', '25squeeze_final_bits_secret') if tail else ('14squeeze_secret',)
                require(name in callees and any(token in name for token in expected), 'bound secret reader producer')
                require('sret([24 x i8])' in args[0], 'actual returned secret descriptor')
                output_index = len(args) - (3 if tail else 2)
                require(comparison.pointer(args[output_index]) == metadata, 'secret reader receives the metadata verification buffer')
                length = args[output_index + 1]
                require(re.fullmatch(r'i64 noundef(?: range\(i64 0, -9223372036854775808\))? ' + re.escape(requested), length),
                        'secret reader receives the matching byte count')
                producers.append(label)
    require(len(producers) == 1, 'unique secret-output descriptor producer')
    return producers[0]


def inspect(function, names, defined, callees):
    trace = Trace(function, names, defined)
    roles, slots = set(), set()
    for label, role, args in trace.comparisons:
        if role != 'ACCUMULATE':
            continue
        difference, actual, expected = [comparison.pointer(arg) for arg in args]
        trace.difference(difference, label)
        rhs = trace.definitions.get(actual, ('', ''))[1]
        bulk = rhs.startswith('getelementptr ')
        require(('bulk' if bulk else 'tail') not in roles, 'one bulk and one final-byte comparison')
        roles.add('bulk' if bulk else 'tail')
        if bulk:
            left = trace.match(actual, r'getelementptr inbounds nuw i8, ptr (' + SSA + r'), i64 (' + SSA + ')')
            right = trace.match(expected, r'getelementptr inbounds nuw i8, ptr (' + SSA + r'), i64 (' + SSA + ')')
            require(left[2] == right[2], 'bulk operands share the same byte index')
            index_entries = trace.phi(left[2], 'i64')
            require(sum(value == '0' for value, _ in index_entries) == 1, 'paired-byte indexing starts at zero')
            next_index = next(value for value, _ in index_entries if value != '0')
            trace.match(next_index, r'add nuw nsw i64 ' + re.escape(left[2]) + r', 1')
            slot = trace.output(left[1])
            chunk = right[1]
            entries = trace.phi(chunk, 'ptr')
            loads = [(value, block) for value, block in entries if trace.definitions.get(value, ('', ''))[1].startswith('load ptr,')]
            require(len(loads) == 1, 'candidate starts from one input pointer')
            trace.candidate(loads[0][0], 'ptr', 0)
            step = next(value for value, _ in entries if value != loads[0][0])
            advance = trace.match(step, r'getelementptr inbounds nuw i8, ptr ' + re.escape(chunk) + r', i64 (' + SSA + ')')
            width = advance[1]
            remaining = trace.match(width, r'call noundef i64 @llvm.umin.i64\(i64 (' + SSA + r'), i64 64\)')[1]
            remaining_entries = trace.phi(remaining, 'i64')
            feedback = next(value for value, block in remaining_entries if block != loads[0][1])
            trace.match(feedback, r'sub nuw(?: nsw)? i64 ' + re.escape(remaining) + ', ' + re.escape(width))
            require({block for _, block in entries} == {block for _, block in remaining_entries}, 'chunk pointer and remaining-count feedback agree')
            producer = output_producer(trace, slot, trace.owner, width, False, callees)
            require(producer == trace.definitions[chunk][0], 'each candidate chunk has its matching secret squeeze')
        else:
            if rhs.startswith('select '):
                select = trace.match(actual, r'select i1 (' + SSA + r'), ptr inttoptr \(i64 1 to ptr\), ptr (' + SSA + ')')
                trace.match(select[1], r'icmp eq ptr ' + re.escape(select[2]) + ', null')
                actual = select[2]
            slot = trace.output(actual)
            end = trace.match(expected, r'getelementptr i8, ptr (' + SSA + r'), i64 -1')[1]
            final = trace.match(end, r'getelementptr i8, ptr (' + SSA + r'), i64 (' + SSA + ')')
            trace.candidate(final[1], 'ptr', 0)
            trace.candidate(final[2], 'i64', 8)
            output_producer(trace, slot, trace.owner, '1', True, callees)
        require(slot not in slots, 'separate bulk and final secret-output descriptors')
        slots.add(slot)
    require(roles == {'bulk', 'tail'}, 'complete comparison operand inventory')
    return trace


def reader_symbols(text):
    defined = comparison.definitions(text)
    result = set(defined)
    for line in text.splitlines():
        method = '25squeeze_final_bits_secret' if '11accelerated' in line and '25squeeze_final_bits_secret' in line else '14squeeze_secret'
        if not (line.startswith('@') and '8in_place3xof' in line and method in line and ' alias ' in line):
            continue
        tail = method == '25squeeze_final_bits_secret'
        abi = 'ptr, ptr, ptr, i64' + (', i8' if tail else '')
        alias = re.fullmatch(r'@([^ ]+) = unnamed_addr alias void \(' + abi + r'\), ptr @([^ ]+)', line)
        require(alias is not None, 'reviewed reader alias ABI')
        name, target = alias.groups()
        require(name not in result and target in defined, 'unique reader alias with defined target')
        source_kind = re.search(r'(?:14Shake|15Cshake)(128|256)Reader' + method, name)
        target_kind = re.search(r'14Shake(128|256)Reader' + method, target)
        accelerated = '11accelerated' in name
        require(source_kind is not None and target_kind is not None and '8in_place3xof' in target
                and accelerated == ('11accelerated' in target)
                and (target_kind[1] == '128' if accelerated else source_kind[1] == target_kind[1]),
                'reviewed reader alias family/rate mapping')
        header = defined[target].splitlines()[0]
        args = comparison.arguments(header, header.index('(') + 1)
        require(header.startswith('define void @') and len(args) == (5 if tail else 4)
                and 'sret([24 x i8])' in args[0]
                and all(arg.startswith('ptr ') for arg in args[:3]) and args[3].startswith('i64 ')
                and (not tail or args[4].startswith('i8 ')),
                'reader alias target ABI')
        result.add(name)
    return result


def cases(record):
    for row, names, defined, _, verifiers in early.cases(record):
        paths = [record.parent / path for path in row['artifacts']
                 if Path(path).name.startswith('brynja_hash_sha3-') and path.endswith('.ll')]
        require(len(paths) == 1, 'unique validated SHA-3 artifact')
        callees = defined | reader_symbols(paths[0].read_text())
        for function in verifiers:
            yield row, function, names, defined, callees


def main(record):
    before = comparison.capture.sources()
    count = definitions = 0
    for _, function, names, defined, callees in cases(record):
        trace = inspect(function, names, defined, callees)
        definitions += len(trace.used)
        count += 1
    require((count, definitions) == (24, 744) and before == comparison.capture.sources(), 'complete unchanged operand-routing matrix')
    print(f'KMAC operand routes: {count} verifiers, 48 accumulation sites, 48 bound reader producers and {definitions} selected SSA definitions PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Routing under reader-result contracts; not full loop/bounds proof, intervening alias effects, callee output correctness, machine spills or native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
