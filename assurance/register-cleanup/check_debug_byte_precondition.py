#!/usr/bin/env python3
"""Check retained debug byte-alignment normal paths, not pointer validity/panics."""
import argparse
import json
from pathlib import Path
import re

import check_debug_clear_assembly as entry

comparison = entry.comparison
require = entry.require
model = entry.llvm.model

# Closed normal-path contracts. With the caller's alignment = 1, ctpop = 1
# and address & (alignment - 1) = 0 for every address representation. No
# allocation validity or null check is inferred from that alignment predicate.
OLD = {
    'start': '''%pieces.dbg.spill1 = alloca [8 x i8], align 8
%1 = alloca [4 x i8], align 4
%ptr.dbg.spill = alloca [8 x i8], align 8
%pieces.dbg.spill = alloca [8 x i8], align 8
%msg.dbg.spill = alloca [16 x i8], align 8
%align.dbg.spill = alloca [8 x i8], align 8
%addr.dbg.spill = alloca [8 x i8], align 8
%_9 = alloca [48 x i8], align 8
%_7 = alloca [16 x i8], align 8
%_5 = alloca [48 x i8], align 8
store ptr %addr, ptr %addr.dbg.spill, align 8
store i64 %align, ptr %align.dbg.spill, align 8
store ptr @alloc_c848f501c9a24e1e115677405b6cf8e4, ptr %msg.dbg.spill, align 8
%2 = getelementptr inbounds i8, ptr %msg.dbg.spill, i64 8
store i64 215, ptr %2, align 8
store ptr @alloc_e92e94d0ff530782b571cfd99ec66aef, ptr %pieces.dbg.spill, align 8
store ptr %addr, ptr %ptr.dbg.spill, align 8
%3 = call i64 @llvm.ctpop.i64(i64 %align)
%4 = trunc i64 %3 to i32
store i32 %4, ptr %1, align 4
%_13 = load i32, ptr %1, align 4
%5 = icmp eq i32 %_13, 1
br i1 %5, label %bb3, label %bb4''',
    'bb3': '''%_11 = ptrtoint ptr %addr to i64
%_12 = sub i64 %align, 1
%_10 = and i64 %_11, %_12
%6 = icmp eq i64 %_10, 0
br i1 %6, label %bb1, label %bb2''',
    'bb1': 'ret void',
}
NEW = {
    'start': '''%msg.dbg.spill = alloca [16 x i8], align 8
%ptr.dbg.spill = alloca [8 x i8], align 8
%align.dbg.spill = alloca [8 x i8], align 8
%addr.dbg.spill = alloca [8 x i8], align 8
store ptr %addr, ptr %addr.dbg.spill, align 8
store i64 %align, ptr %align.dbg.spill, align 8
store ptr %addr, ptr %ptr.dbg.spill, align 8
%_3 = invoke zeroext i1 @ALIGN(ptr %addr, i64 %align)
to label %bb3 unwind label %terminate''',
    'bb3': 'br i1 %_3, label %bb1, label %bb2',
    'bb1': 'ret void',
}
ALIGN = {
    'start': '''%s.dbg.spill = alloca [16 x i8], align 8
%align.dbg.spill = alloca [8 x i8], align 8
%self.dbg.spill = alloca [8 x i8], align 8
store ptr %self, ptr %self.dbg.spill, align 8
store i64 %align, ptr %align.dbg.spill, align 8
%0 = call i64 @llvm.ctpop.i64(i64 %align)
%_8 = trunc i64 %0 to i32
%1 = icmp eq i32 %_8, 1
br i1 %1, label %bb1, label %bb2''',
    'bb1': '''%_6 = ptrtoint ptr %self to i64
%_7 = sub i64 %align, 1
%_5 = and i64 %_6, %_7
%_0 = icmp eq i64 %_5, 0
ret i1 %_0''',
}


def contracts(compiler):
    require(compiler in ('1.90.0', '1.98.1'), 'reviewed byte-precondition compiler')
    return {'CHECK': OLD} if compiler == '1.90.0' else {'CHECK': NEW, 'ALIGN': ALIGN}


def select(core, compiler):
    _, precondition, selected = entry.llvm.closure(core)
    functions = {'CHECK': selected[precondition]}
    names = {'CHECK': precondition}
    if compiler == '1.98.1':
        candidates = [(name, body) for name, body in comparison.definitions(core).items()
                      if '13is_aligned_to' in name]
        require(len(candidates) == 1, 'unique retained alignment callee')
        names['ALIGN'], functions['ALIGN'] = candidates[0]
    return functions, names


def inspect(functions, names, compiler):
    expected = contracts(compiler)
    require(set(functions) == set(names) == set(expected), 'complete byte-precondition normal-path inventory')
    count = 0
    for role, graph in expected.items():
        function = functions[role]
        header = function.splitlines()[0]
        symbol = re.search(comparison.SYMBOL, header)
        require(symbol is not None and symbol[1] == names[role], 'bound precondition function identity')
        args = comparison.arguments(header, symbol.end())
        require(args == (['ptr %addr', 'i64 %align', 'ptr align 8 %0'] if role == 'CHECK'
                         else ['ptr %self', 'i64 %align']), 'borrowed pointer and alignment ABI')
        require(header.startswith('define internal void ' if role == 'CHECK' else 'define zeroext i1 '),
                'precondition return ABI')
        actual = model.blocks(function)
        for block, instructions in graph.items():
            require(len(re.findall(r'^' + re.escape(block) + ':', function, re.M)) == 1,
                    'unique normal-path block')
            require(block in actual, 'retained normal-path block')
            lines = actual[block]
            if role == 'CHECK' and compiler == '1.98.1':
                lines = [line.replace('@' + names['ALIGN'] + '(', '@ALIGN(') for line in lines]
            require(lines == instructions.splitlines(), 'exact byte-alignment normal path: ' + role + '/' + block)
            count += len(lines)
    return count


def cases(record):
    for core, compiler, assembly, arm in entry.llvm.writing.cases(record):
        functions, names = select(core, compiler)
        yield core, assembly, functions, names, compiler, arm


def main(record):
    before = comparison.capture.sources()
    builds = paths = instructions = lengths = 0
    for core, assembly, functions, names, compiler, arm in cases(record):
        instructions += inspect(functions, names, compiler)
        paths += len(functions)
        # The caller, not this precondition, establishes live borrowed storage.
        # Recheck the real emitted call supplies alignment one and a zero byte.
        caller_names = entry.identities(core)
        pair = {role: entry.select(assembly, caller_names[role]) for role in ('ENTRY', 'WRITE')}
        locations = set(re.findall(r'\.Lalloc_[0-9a-f]+', pair['ENTRY']))
        require(len(locations) == 1, 'single entry source location')
        entry.inspect(pair, caller_names, locations.pop(), arm)
        lengths += entry.llvm.inspect(core)
        builds += 1
    require(builds == 8 and before == comparison.capture.sources(), 'complete unchanged byte-precondition matrix')
    print(f'Debug byte preconditions: {paths} normal-return paths, {instructions} LLVM instructions across {builds} builds PASS')
    print(f'Caller assembly rechecked; {lengths} existing LLVM length cases repeated; alignment-one predicate is address-independent')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Not pointer validity/null enforcement, precondition machine-code qualification, panic/unwind coverage or whole-call erasure; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
