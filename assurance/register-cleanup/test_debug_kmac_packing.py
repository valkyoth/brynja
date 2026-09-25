#!/usr/bin/env python3
"""Actual KMAC packing regressions and independent public arithmetic checks."""
import argparse
from pathlib import Path
from unittest.mock import patch

import check_debug_kmac_packing as check
from debug_kmac_packing import PackingModel, lower
from test_debug_accelerated_model import rejects


def arithmetic():
    # Pure instruction handlers do not access model memory or instantiate a
    # compiler/runtime process. Exhaust both operands of their byte domain.
    m = object.__new__(PackingModel)
    for left in range(256):
        for right in range(256):
            for op, result in (('add', left + right), ('sub', left - right)):
                name = 'diagnostic_u8_' + op
                assert m.run(name, [left, right]) == result % 256
                if 0 <= result < 256:
                    assert m.run(name + '_nuw', [left, right]) == result
                else:
                    rejects(lambda: m.run(name + '_nuw', [left, right]))
            assert m.run('llvm.uadd.with.overflow.i8', [left, right]) == ((left + right) % 256, int(left + right >= 256))
    assert lower('%x = mul i64 %y, 1') == '%x = add i64 %y, 0'
    for flags in (' nuw', ' nsw', ' nuw nsw'):
        assert lower('%x = mul' + flags + ' i64 %y, 1') == '%x = add i64 %y, 0'
        assert lower('%x = mul' + flags + ' i64 %y, 2') == '%x = mul' + flags + ' i64 %y, 2'
    assert lower('%x = mul i64 %y, 2') == '%x = mul i64 %y, 2'
    assert lower('%x = sub nuw i8 %a, %b') == '%x = call i8 @diagnostic_u8_sub_nuw(i8 %a, i8 %b)'
    print('Packing diagnostic byte arithmetic: all 65,536 operand pairs and nonpoison boundaries PASS', flush=True)


def main(record):
    arithmetic()
    before = check.whole.comparison.capture.sources()
    count = controls = 0
    for case in check.whole.retained.cases(record):
        function, definitions, names, text = case
        baseline = check.inspect(*case, fast=True)
        linked = check.closure(*case)
        selected = [name for name in linked[1] if 'SecretPacker' in name and
                    any(token in name for token in ('15push_bit_string', '10push_bytes', '9push_bits', '5flush', '8set_used'))
                    and '%self' in definitions[name].splitlines()[0]
                    and 'closure' not in name and 'core6result' not in name]
        # Derive success from the same independently checked root layout used
        # by the positive campaign; wrong payload effects must still reject.
        suffix = next(name for name in linked[1] if '13append_suffix' in name)
        code = check.re.findall(r'icmp eq i8 %[-.$\w]+, (7|20|-1)\b', definitions[suffix])[0]
        for name in selected:
            header = definitions[name].splitlines()[0]
            if 'define void @' in header:
                value = 'ret void'
            elif 'define i8 @' in header:
                value = 'ret i8 ' + code
            else:
                raise AssertionError('unexpected selected packer helper ABI: ' + header)
            changed = header + '\nstart:\n  ' + value + '\n}'
            count += rejects(lambda: check.inspect(function, {**definitions, name: changed}, names, text, fast=True))
        assert check.inspect(function.replace('start:\n', 'start:\n; harmless annotation\n', 1),
                             definitions, names, text, fast=True) == baseline
        controls += 1
        print(f'Actual KMAC packer regressions: {controls}/24 paths; {count} rejected PASS', flush=True)
    assert (controls, count) == (24, 120), (controls, count)
    assert before == check.whole.comparison.capture.sources()
    print(f'Packing totals: {count} rejected actual-helper mutants; {controls} controls')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
