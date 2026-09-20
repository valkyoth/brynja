#!/usr/bin/env python3
"""Mutate retained debug writes/helpers; never rebuild or execute Rust."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_output_write as check
from test_kmac_verify_comparisons import rejects, assembly_mutants


def mutants(core, compiler):
    root, _, functions = check.closure(core)
    body = functions[root]
    for old, new in (
        ('icmp eq i64', 'icmp ne i64'),
        ('ptr %self, i64 16', 'ptr %self, i64 8'),
        ('i64 %input.1, i64 %region.1', 'i64 %region.1, i64 %input.1'),
        ('store i8 3, ptr %_0', 'store i8 2, ptr %_0'),
        ('store i8 2, ptr %_0', 'store i8 3, ptr %_0'),
        ('start:', 'start:\n  %leak = load i8, ptr %input.0, align 1'),
    ):
        yield 'write guard/argument/payload regression', core.replace(body, body.replace(old, new))
    copy_line = next(line for line in body.splitlines() if 'call ' in line and 'secret_memory_transfer4copy' in line)
    yield 'wrong caller source', core.replace(body, body.replace(copy_line, copy_line.replace('%input.0', '%destination.0')))
    yield 'by-value owner ABI', core.replace(body, body.replace('ptr align 8 %self,', 'ptr byval([24 x i8]) align 8 %self,'))
    for branch in (line for line in body.splitlines() if line.strip().startswith('br i1')):
        edges = re.search(r'br i1 (\S+), label %(\S+), label %([^,\s]+)', branch)
        changed = branch.replace(edges[0], f'br i1 {edges[1]}, label %{edges[3]}, label %{edges[2]}')
        yield 'inverted write branch', core.replace(body, body.replace(branch, changed))
    commit = [line for line in body.splitlines() if re.search(r'store i64 %\d+, ptr %\d+,', line)][-1]
    for changed in ('', commit + '\n' + commit, re.sub(r'store i64 %\d+', 'store i64 %input.1', commit)):
        yield 'missing/duplicate/incorrect progress commit', core.replace(body, body.replace(commit, changed))
    success = '4' if compiler == '1.90.0' else '-1'
    yield 'failure mutates owner progress', core.replace(body, body.replace(
        'store i8 3, ptr %_0', 'store i64 0, ptr %self, align 8\n  store i8 3, ptr %_0'))
    yield 'wrong success discriminant', core.replace(body, body.replace('store i8 ' + success + ',', 'store i8 0,'))
    for name, function in functions.items():
        replacements = []
        if 'checked_write_end' in name:
            replacements = [('icmp ugt i64', 'icmp uge i64'),
                            ('store i8 1,', 'store i8 0,'),
                            ('store i8 2,', 'store i8 3,'),
                            ('store i64 %end,', 'store i64 %input_len,')]
        elif 'checked_add' in name:
            if compiler == '1.90.0':
                replacements = [('extractvalue { i64, i1 } %0, 1', 'extractvalue { i64, i1 } %0, 0')]
            else:
                replacements = [('icmp ult i64', 'icmp ugt i64'), ('add i64', 'add nuw i64')]
        elif 'as_deref' in name:
            replacements = [('icmp eq i64', 'icmp ne i64')]
        elif '5deref' in name or '9deref_mut' in name:
            replacements = [('ptr %self, i64 8', 'ptr %self, i64 16')]
        elif 'SecretRegionInitialization5write' in name and '%_1.0' in function.splitlines()[0]:
            replacements = [('load i64, ptr %_1.0', 'load i64, ptr %_1.1')]
        elif 'secret_memory_transfer4copy' in name:
            replacements = [('icmp ne i64', 'icmp eq i64'),
                            ('ptr %input.0, i64 %input.1)', 'ptr %destination.0, i64 %input.1)'),
                            ('store i8 ' + success + ',', 'store i8 2,')]
        elif '7get_mut' in name and '%slice.0' in function.splitlines()[0]:
            replacements = [('ptr %slice.0, i64 %self.0', 'ptr %slice.0, i64 %self.1'),
                            ('sub nuw i64 %self.1, %self.0', 'sub nuw i64 %self.1, %self.1')]
        for old, new in replacements:
            yield 'actual helper regression: ' + old, core.replace(function, function.replace(old, new))


def model_tests():
    m = check.model.Model({}, '', 'copy')
    owner = m.allocate('owner', 24)
    payload = m.allocate('secret', 8, payload=True)
    for operation in (lambda: m.load(payload, 1), lambda: m.store(payload, 1, 0),
                      lambda: m.load(check.model.Pointer('owner', 24), 1)):
        try:
            operation()
        except ValueError:
            pass
        else:
            raise AssertionError('invalid memory access accepted')
    m.store(owner, 8, payload)
    assert m.load(owner, 8) == payload
    assert m.load(check.model.Pointer('owner', 8), 8) is check.model.UNKNOWN
    assert m.run('llvm.uadd.with.overflow.i64', [check.model.MASK, 1]) == (0, 1)
    assert m.run('llvm.uadd.with.overflow.i64', [check.model.MASK, 0]) == (check.model.MASK, 0)


def main(record):
    model_tests()
    count = assembly_count = controls = 0
    for core, compiler, assembly, arm in check.cases(record):
        count += rejects(lambda text: check.inspect(text, compiler), core, mutants(core, compiler))
        assembly_count += rejects(lambda text: check.copy_boundary.inspect(text, arm), assembly,
                                  assembly_mutants(assembly, 'COPY', arm))
        # Debug metadata and comments do not alter the evaluated instructions.
        root, _, functions = check.closure(core)
        body = functions[root]
        changed = re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M)
        assert changed != body
        assert check.inspect(core.replace(body, changed), compiler) == len(list(check.scenarios())) + 5
        controls += 1
        for name, function in functions.items():
            if 'as_deref' in name:
                changed = function.replace('ptr %self, i64 8', 'ptr %self, i64 16')
                assert changed != function
                # This pre-discriminant length load is unused. The real deref
                # helper subsequently reloads the correct original descriptor.
                assert check.inspect(core.replace(function, changed), compiler) == len(list(check.scenarios())) + 5
                controls += 1
    if (count, assembly_count, controls) != (260, 40, 24):
        raise AssertionError(f'incomplete debug write campaign: {count}/{assembly_count}/{controls}')
    print(f'Debug writes reject {count} LLVM and {assembly_count} copy-assembly mutations; {controls} metadata/unused-load controls PASS')
    print('Artifact-text/model tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
