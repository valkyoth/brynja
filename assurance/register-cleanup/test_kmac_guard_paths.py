#!/usr/bin/env python3
"""Guard glue and explicit debug-CFG mutations; retained text only."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_guard_paths as check
import test_kmac_metadata_assembly as assembly_tests
import test_kmac_metadata_clear as metadata_tests
from test_kmac_verify_comparisons import rejects


def glue_mutants(function, names):
    # Reuse call/width/offset/payload/return mutations without changing shared tests.
    for label, mutant in metadata_tests.mutants(function, 'GLUE', names):
        if mutant != function:
            yield label, mutant
    if '%_1.0.val' in function:
        yield 'inverted nonnull assumption', function.replace('icmp ne ptr ', 'icmp eq ptr ', 1)
        yield 'wrong promoted glue ABI', function.replace('define internal fastcc void ', 'define void ', 1)
    else:
        yield 'wrong borrowed input name', function.replace('%_1', '%other')


def cfg_mutants(function, glue_name):
    graph = check.metadata.model.blocks(function)
    exits = [label for label, lines in graph.items() if lines[-1].startswith('ret ')]
    assert len(exits) == 1
    target = exits[0]
    initializer = next(line for lines in graph.values() for line in lines
                       if re.fullmatch(r'store ptr ' + check.SSA + r', ptr %cleanup, align 8', line))
    operation_label = next(label for label, lines in graph.items()
                           if any('33accumulate_secret_byte_difference' in line for line in lines))
    start_edges = graph['start'][-1]
    normal, _ = check.metadata.model.shared.edges(start_edges)
    yield 'selected operation reached before initialization', function.replace(
        start_edges, start_edges.replace('label %' + normal, 'label %' + operation_label, 1), 1)
    yield 'missing guard initialization', function.replace(initializer, '', 1)
    yield 'repeated guard overwrite', function.replace(initializer, initializer + '\n' + initializer, 1)
    yield 'wrong descriptor width', function.replace('%cleanup = alloca [8 x i8]', '%cleanup = alloca [16 x i8]', 1)
    yield 'unbound guard glue identity', function.replace('@' + glue_name + '(', '@unreviewed_guard(', 1)
    for lines in graph.values():
        for line in lines:
            if '@' + glue_name + '(' in line:
                yield 'wrong guard descriptor', function.replace(line, line.replace('%cleanup', '%reader'), 1)
                yield 'removed guard invocation', function.replace(line, '', 1)
                yield 'lost invocation terminator', function.replace(line, line.replace('invoke ', 'call ', 1), 1)
        if not any(any(token in line for token in ('33accumulate_secret_byte_difference', '25secret_difference_is_zero',
                                                   '12final_secret', '6secret')) and 'invoke ' in line for line in lines):
            continue
        edges = lines[-1]
        normal, unwind = check.metadata.model.shared.edges(edges)
        for old in (normal, unwind):
            changed = edges.replace('label %' + old, 'label %' + target, 1)
            assert changed != edges
            yield 'normal/unwind cleanup bypass', function.replace(edges, changed, 1)
        operation = lines[-2]
        name, _ = check.call(operation)
        yield 'unbound operation definition', function.replace(operation, operation.replace('@' + name + '(', '@unreviewed_' + name.strip('"') + '('), 1)
    yield 'premature initialized return', function.replace(initializer, initializer + '\n  ret { i1, i8 } undef', 1)
    yield 'dangling cleanup edge', function.replace('unwind label %cleanup9', 'unwind label %missing', 1)


def main(record):
    llvm_count = asm_count = extraction_count = cfg_count = controls = builds = verifiers_checked = 0
    for row, functions, names, body, verifiers, definitions in check.cases(record):
        compiler = row['compiler'].splitlines()[0].split()[1]
        profile, arm = row['profile'], row['target'].startswith('aarch64-')
        inspect = lambda value: check.glue({**functions, 'GLUE': value}, names, body, compiler, profile, arm)
        llvm_count += rejects(inspect, functions['GLUE'], glue_mutants(functions['GLUE'], names))
        names_asm = {role: name.strip('"') for role, name in names.items()}
        inspect_asm = lambda value: check.glue(functions, names, value, compiler, profile, arm)
        asm_count += rejects(inspect_asm, body, assembly_tests.mutations(body, 'GLUE', names_asm, arm))
        select = lambda value: check.assembly.assembly.select(value, names_asm['GLUE'])
        extraction_count += rejects(select, body, [
            ('duplicate glue definition', body + '\n' + body),
            ('absent glue definition', body.replace(names_asm['GLUE'] + ':', 'other:', 1)),
            ('missing glue end', re.sub(r'\.Lfunc_end\d+:$', '', body)),
        ])
        original = check.glue(functions, names, body, compiler, profile, arm)
        comment = functions['GLUE'].replace('start:\n', 'start:\n; harmless comment\n', 1)
        assert inspect(comment) == original
        controls += 1
        for function in verifiers:
            inspect_cfg = lambda value: check.debug_paths(value, names['GLUE'], definitions)
            cfg_count += rejects(inspect_cfg, function, cfg_mutants(function, names['GLUE']))
            baseline = inspect_cfg(function)
            renamed = re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function)
            no_debug = re.sub(r'(?m)^\s*#dbg_[^\n]*\n', '', function)
            for value in (renamed, no_debug):
                assert value != function and inspect_cfg(value) == baseline
                controls += 1
            verifiers_checked += 1
        builds += 1
    assert (builds, verifiers_checked, llvm_count, asm_count, extraction_count, cfg_count, controls) == (
        16, 24, 376, 628, 48, 744, 64), (builds, verifiers_checked, llvm_count, asm_count,
                                      extraction_count, cfg_count, controls)
    print(f'KMAC guard paths reject {llvm_count} glue LLVM, {asm_count} glue assembly, {extraction_count} extraction and {cfg_count} caller-CFG mutations; {controls} controls PASS')
    print('Subprocess execution forbidden; invocation coverage is not successful cleanup or whole-call erasure')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
