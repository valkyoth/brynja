#!/usr/bin/env python3
"""Retained KMAC cleanup assembly mutations; no rebuilding or binary execution."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_metadata_assembly as check
from test_kmac_verify_comparisons import rejects


def mutations(body, role, names, arm):
    lines = body.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(('.', '_')):
            continue
        yield 'missing machine instruction', '\n'.join(lines[:index] + lines[index + 1:])
        yield 'duplicated machine instruction', '\n'.join(lines[:index] + [line, line] + lines[index + 1:])
        if re.search(r'(?<!\w)[#$]-?\d+', line):
            changed = re.sub(r'(?<!\w)([#$])(-?\d+)', lambda m: m[1] + str(int(m[2]) + 1), line, count=1)
            yield 'wrong immediate/width/offset/predicate', '\n'.join(lines[:index] + [changed] + lines[index + 1:])
    for name in names.values():
        if name != names[role] and name in body:
            yield 'callee shares reviewed name prefix', body.replace(name, name + '_unreviewed')
    extras = (('ldrb w3, [x0]', 'str x0, [x1]', 'bl unreviewed', 'movi v0.16b, #0', '.byte 0')
              if arm else ('movb (%rdi), %dl', 'movq %rdi, (%rsi)', 'callq unreviewed',
                           'vpxor %ymm0, %ymm0, %ymm0', '.byte 0'))
    for extra in extras:
        yield 'payload/escape/call/vector/data injection', body.replace('\n', '\n\t' + extra + '\n', 1)
    for directive in ('.loc 1 1 1', '.file 1 "source" "file.rs"', '.cfi_offset %rbx, -24'):
        yield 'instruction hidden after metadata', body.replace('\n', '\n\t' + directive + '; ' + extras[0] + '\n', 1)
    branches = re.findall(r'(?m)^[ \t]*(?:jne|je|tbnz|cbz)[ \t]+[^\n]+', body)
    for branch in branches:
        changed = re.sub(r'\b(jne|je|tbnz|cbz)\b', lambda m: {'jne': 'je', 'je': 'jne', 'tbnz': 'tbz', 'cbz': 'cbnz'}[m[1]], branch, count=1)
        yield 'reversed empty/nonempty predicate', body.replace(branch, changed, 1)
    yield 'wrong function boundary', body.replace(names[role] + ':', names[role] + '_other:', 1)


def main(record):
    count = boundaries = controls = builds = functions_checked = 0
    for _, _, bodies, names, arm, profile, compiler in check.cases(record):
        expected_count = check.inspect(bodies, names, arm, profile, compiler)
        for role, body in bodies.items():
            inspect = lambda value: check.inspect({**bodies, role: value}, names, arm, profile, compiler)
            count += rejects(inspect, body, mutations(body, role, names, arm))
            spaced = '\n'.join('  ' + line.strip().replace('\t', '   ') if line.startswith('\t') else line
                               for line in body.splitlines())
            renamed = re.sub(r'\.LBB(\d+)_', lambda m: '.LBB' + str(int(m[1]) + 1000) + '_', body)
            no_locations = re.sub(r'(?m)^[ \t]*\.loc[ \t]+[^\n]*\n', '', body)
            # Unwind metadata is explicitly not qualified by this inspector.
            no_cfi = re.sub(r'(?m)^[ \t]*\.cfi_[^\n]*\n', '', body)
            for value in (spaced, renamed, no_locations, no_cfi):
                if value != body:
                    assert inspect(value) == expected_count
                    controls += 1
            select = lambda value: check.assembly.select(value, names[role])
            boundaries += rejects(select, body, [
                ('duplicate definition', body + '\n' + body),
                ('missing definition', body.replace(names[role] + ':', 'other:', 1)),
                ('missing function end', re.sub(r'\.Lfunc_end\d+:$', '', body)),
            ])
            functions_checked += 1
        builds += 1
    assert (builds, functions_checked, count, boundaries, controls) == (16, 72, 3088, 216, 200), (
        builds, functions_checked, count, boundaries, controls)
    print(f'KMAC metadata assembly rejects {count} instruction/callee/identity and {boundaries} extraction mutations; {controls} scoped controls across {functions_checked} functions PASS')
    print('Text mutations only; subprocess execution forbidden; unwind metadata deliberately outside scope')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
