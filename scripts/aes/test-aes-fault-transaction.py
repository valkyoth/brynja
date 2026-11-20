#!/usr/bin/env python3
"""Runner regression tests; fixtures are NOT executable fault simulations."""
from contextlib import redirect_stdout, redirect_stderr
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('transaction_probe',Path(__file__).with_name('check-aes-fault-transaction.py'))
TX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TX)


def transcript(case, path='public'):
    secret = path == 'secret'
    entry = case == 'invalid-entry-state'
    staging = case == 'staging-after-write'
    combined = case == 'combined-decision-bypass'
    late = case == 'after-final-check-negative-control'
    bypasses = 2 if case == 'two-readbacks-bypass' else int('readback' in case)
    stops = 1+int(not entry)+bypasses+int(late)+int(combined)
    breakpoints = 1+int(not entry)+int(bool(bypasses or late or combined))
    result = (TX.SECRET_TEST if secret else TX.TEST)+'\nBRYNJA_TRANSACTION_EVIDENCE_CFG=false\n'
    result += ''.join(f'Hardware assisted breakpoint {n+1} at 0x123\n' for n in range(breakpoints))
    result += ''.join(f'Thread 2 hit Breakpoint {min(n+1,breakpoints)}, 0x123\n' for n in range(stops))
    result += 'TX_ENTRY 1\n'
    if staging: result += 'TX_STAGING 1\n'
    elif not entry: result += 'TX_COPY 1\n'
    if case != 'baseline': result += 'TX_MUTATED 1\n'
    result += 'TX_CHECK_FAILED 1\nTX_BYPASSED 1\n'*bypasses
    if late: result += 'TX_LATE 1\n'
    if combined: result += 'TX_COMBINED_FAILED 1\nTX_COMBINED_BYPASSED 1\n'
    if case.endswith('negative-control'):
        result += 'left: [67, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66]\n'
        result += 'test result: FAILED. 0 passed; 1 failed; 0 ignored;\nexited with code 0145\n'
    else:
        accepted = 'BRYNJA_SECRET_ACCEPTED_CLEARED' if secret else 'BRYNJA_TRANSACTION_ACCEPTED'
        rejected = 'BRYNJA_SECRET_REJECTED_CLEARED_RETIRED' if secret else 'BRYNJA_TRANSACTION_REJECTED_RESTORED_RETIRED'
        result += (accepted if case == 'baseline' else rejected)+'\n'
        result += 'test result: ok. 1 passed; 0 failed; 0 ignored;\nexited normally\n'
    return result


class TransactionRunner(unittest.TestCase):
    def test_symbol_hashes_duplicates_and_return_sites(self):
        normal = f'1000 <{TX.ROOT}>:\n 1000: push %rbp\n 1001: ret\n 1002: int3\n'
        self.assertEqual(TX.body(normal,TX.ROOT)['ret'],1)
        hashed = normal.replace(TX.ROOT,TX.ROOT+'::h1234567890abcdef')
        self.assertEqual(TX.body(hashed,TX.ROOT)['ret'],1)
        for bad in ['',normal+hashed,normal.replace('ret','nop'),normal.replace('1002: int3','1002: ret'),
                    normal.replace('1001: ret','unparsed'),normal.replace('1001:','1000:')]:
            with self.assertRaises(ValueError): TX.body(bad,TX.ROOT)

    def test_all_cases_require_exact_checkpoints(self):
        for case in TX.CASES:
            good = transcript(case)
            TX.validate(good,case)
            for line in good.splitlines():
                if line.startswith('TX_'):
                    with self.assertRaises(ValueError): TX.validate(good.replace(line+'\n','',1),case)
                    with self.assertRaises(ValueError): TX.validate(good.replace(line,line.replace(' 1',' 0'),1),case)
            for old,new in [('Hardware assisted breakpoint','Breakpoint'),('hit Breakpoint','missed Breakpoint'),
                            ('EVIDENCE_CFG=false','EVIDENCE_CFG=true')]:
                with self.assertRaises(ValueError): TX.validate(good.replace(old,new),case)
            with self.assertRaises(ValueError): TX.validate(good+good,case)

    def test_wrong_outcomes_and_false_controls_are_rejected(self):
        for case in TX.CASES:
            good = transcript(case)
            if case.endswith(('negative-control','counterexample')):
                bad = good.replace('67, 66','66, 66')
            elif case == 'baseline':
                bad = good.replace('BRYNJA_TRANSACTION_ACCEPTED','BRYNJA_TRANSACTION_REJECTED_RESTORED_RETIRED')
            else:
                bad = good.replace('BRYNJA_TRANSACTION_REJECTED_RESTORED_RETIRED','BRYNJA_TRANSACTION_ACCEPTED')
            with self.assertRaises(ValueError): TX.validate(bad,case)
            with self.assertRaises(ValueError): TX.validate(good.replace('test result:','missing result:'),case)
        with self.assertRaises(ValueError): TX.validate('', 'unknown')

    def test_commands_keep_baseline_mutation_free_and_use_hardware_stops(self):
        root,check = dict(symbol=TX.ROOT,ret=100),dict(symbol=TX.CHECK,ret=120)
        offsets = list(range(0,124,4))
        for case in TX.CASES:
            commands = TX.commands(case,root,check,TX.GUARD.SYMBOL,offsets)
            self.assertFalse(any(c.startswith('break ') for c in commands))
            if case == 'baseline':
                self.assertFalse(any(c.startswith(('set *','set $al')) for c in commands))
            self.assertEqual('ignore 3 1' in commands,case == 'output-plus-second-readback-bypass')
        with self.assertRaises(ValueError): TX.commands('unknown',root,check,TX.GUARD.SYMBOL,offsets)

    def test_secret_cases_require_exact_events_and_clear_or_escape_outcomes(self):
        for case in TX.SECRET_CASES:
            good = transcript(case,'secret')
            TX.validate(good,case,'secret')
            for line in good.splitlines():
                if line.startswith(('TX_', 'BRYNJA_SECRET_')):
                    with self.assertRaises(ValueError): TX.validate(good.replace(line+'\n','',1),case,'secret')
                if line.startswith('TX_'):
                    with self.assertRaises(ValueError): TX.validate(good.replace(line,line.replace(' 1',' 0'),1),case,'secret')
            for old,new in [('Hardware assisted breakpoint','Breakpoint'), ('hit Breakpoint','missed Breakpoint'),
                            ('EVIDENCE_CFG=false','EVIDENCE_CFG=true'), ('test result:','missing result:')]:
                with self.assertRaises(ValueError): TX.validate(good.replace(old,new),case,'secret')
            if case.endswith('negative-control'):
                with self.assertRaises(ValueError): TX.validate(good.replace('67, 66','66, 66'),case,'secret')
            with self.assertRaises(ValueError): TX.validate(good+good,case,'secret')

    def test_secret_commands_distinguish_staging_and_actual_destination(self):
        root,check = dict(symbol=TX.SECRET_ROOT,ret=100,combined_decision=80,combined_kind='legacy-or'),dict(symbol=TX.CHECK,ret=120)
        offsets = list(range(0,124,4))
        for case in TX.SECRET_CASES:
            commands = TX.secret_commands(case,root,check,TX.GUARD.SYMBOL,offsets)
            self.assertFalse(any(c.startswith('break ') for c in commands))
            self.assertIn('set $destination=(unsigned char*)$rdx',commands)
            self.assertEqual('ignore 2 2' in commands,case not in ('invalid-entry-state','staging-after-write'))
            if 'readback' in case:
                self.assertLess(commands.index('disable 3'),commands.index('continue'))
                self.assertGreater(commands.index('enable 3'),commands.index('disable 2'))
            if case == 'baseline':
                self.assertFalse(any(c.startswith(('set *','set $al')) for c in commands))
            self.assertEqual('ignore 3 1' in commands,case == 'output-plus-second-readback-bypass')
            if case == 'staging-after-write':
                self.assertIn('set *$staging = *$staging ^ 1',commands)
                self.assertNotIn('set *$destination = *$destination ^ 1',commands)
            if case == 'after-final-check-negative-control':
                self.assertTrue(any('($result+8) == $destination' in c and '($result+16) == 16' in c for c in commands))
            self.assertEqual('set $eflags = $eflags ^ 64' in commands,case == 'combined-decision-bypass')
        with self.assertRaises(ValueError): TX.secret_commands('unknown',root,check,TX.GUARD.SYMBOL,offsets)

    def test_path_and_outcome_substitution_cannot_pass(self):
        for case in TX.CASES:
            with self.assertRaises(ValueError): TX.validate(transcript(case,'public'),case,'secret')
            with self.assertRaises(ValueError): TX.validate(transcript(case,'secret'),case,'public')
        for case in TX.SECRET_CASES:
            if not case.endswith('negative-control'):
                good = transcript(case,'secret')
                a,b = 'BRYNJA_SECRET_ACCEPTED_CLEARED','BRYNJA_SECRET_REJECTED_CLEARED_RETIRED'
                bad = good.replace(a,b) if case == 'baseline' else good.replace(b,a)
                with self.assertRaises(ValueError): TX.validate(bad,case,'secret')
        with self.assertRaises(ValueError): TX.validate('', 'baseline', 'unknown')

    def test_combined_decision_site_is_explicit_not_guessed(self):
        normal = f'1000 <{TX.SECRET_ROOT}>:\n 1000: or %al,%bpl\n 1003: mov $0x1,%r12b\n 1006: jne 1010 <failure>\n 1008: ret\n'
        self.assertEqual(TX.body(normal,TX.SECRET_ROOT)['combined_decision'],6)
        self.assertEqual(TX.body(normal,TX.SECRET_ROOT)['combined_kind'],'legacy-or')
        for old,new in [('or %al,%bpl','and %al,%bpl'), ('jne','je'), ('%r12b','%r11b')]:
            with self.assertRaises(ValueError): TX.body(normal.replace(old,new),TX.SECRET_ROOT)
        duplicate = normal.replace('1008: ret', '1008: or %al,%bpl\n 100b: mov $0x1,%r12b\n 100e: jne 1010 <failure>\n 1010: ret')
        with self.assertRaises(ValueError): TX.body(duplicate,TX.SECRET_ROOT)

        current = (f'1000 <{TX.SECRET_ROOT}>:\n'
                   ' 1000: call 2000 <brynja_crypto::aes::fault_integrity::transaction::validate>\n'
                   ' 1005: mov $0x1,%r12b\n 1008: test %al,%al\n'
                   ' 100a: jne 1010 <failure>\n 100c: ret\n')
        site = TX.body(current,TX.SECRET_ROOT)
        self.assertEqual((site['combined_decision'],site['combined_kind']),(10,'validate-r12b'))
        for old,new in [('::validate>','::check>'), ('test %al,%al','test %bl,%bl'),
                        ('jne','je'), ('%r12b','%r11b')]:
            with self.assertRaises(ValueError): TX.body(current.replace(old,new),TX.SECRET_ROOT)
        with self.assertRaises(ValueError): TX.body(current.replace('100c: ret',
            '100c: or %al,%bpl\n 100f: mov $0x1,%r12b\n 1012: jne 1020 <failure>\n 1014: ret'),TX.SECRET_ROOT)
        commands = TX.secret_commands('combined-decision-bypass',site,
            dict(symbol=TX.CHECK,ret=120),TX.GUARD.SYMBOL,list(range(0,124,4)))
        self.assertTrue(any('($r12 & 255) == 1' in command for command in commands))
        self.assertFalse(any('$bpl == 1' in command for command in commands))

        other = current.replace('%r12b','%bpl')
        site = TX.body(other,TX.SECRET_ROOT)
        self.assertEqual((site['combined_decision'],site['combined_kind']),(10,'validate-bpl'))
        commands = TX.secret_commands('combined-decision-bypass',site,
            dict(symbol=TX.CHECK,ret=120),TX.GUARD.SYMBOL,list(range(0,124,4)))
        self.assertTrue(any('$bpl == 1' in command for command in commands))
        with self.assertRaises(ValueError): TX.secret_commands('combined-decision-bypass',
            dict(symbol=TX.SECRET_ROOT,ret=100,combined_decision=10),
            dict(symbol=TX.CHECK,ret=120),TX.GUARD.SYMBOL,list(range(0,124,4)))
        with self.assertRaises(ValueError): TX.secret_commands('combined-decision-bypass',
            dict(site,combined_kind='unknown'),dict(symbol=TX.CHECK,ret=120),
            TX.GUARD.SYMBOL,list(range(0,124,4)))

    def test_tool_errors_or_invalid_elf_never_publish_observation(self):
        elf = bytearray(32)
        elf[:6] = b'\x7fELF\x02\x01'
        elf[18:20] = b'\x3e\x00'
        for data, error in [(b'invalid',AssertionError('must not execute')),
                            (elf,subprocess.CalledProcessError(1,['objdump'])),
                            (elf,subprocess.TimeoutExpired(['objdump'],30))]:
            output = io.StringIO()
            with patch('sys.argv',['probe','--binary','fixture']), \
                 patch.object(Path,'resolve',return_value=Path('/fixture')), \
                 patch.object(Path,'read_bytes',return_value=data), \
                 patch.object(TX.subprocess,'run',side_effect=error), \
                 redirect_stdout(output),redirect_stderr(io.StringIO()):
                self.assertEqual(TX.main(),2)
            self.assertNotIn('DEVELOPMENT_TRANSACTION_OBSERVED',output.getvalue())

    def test_completed_secret_experiment_reports_combined_bypass_rejected(self):
        elf = bytearray(32)
        elf[:6] = b'\x7fELF\x02\x01'
        elf[18:20] = b'\x3e\x00'
        runs = [subprocess.CompletedProcess(['objdump'],0,'dump','')]
        runs += [subprocess.CompletedProcess(['gdb'],0,transcript(case,'secret'),'') for case in TX.SECRET_CASES]
        metadata = dict(symbol=TX.SECRET_ROOT,ret=100,combined_decision=80,combined_kind='legacy-or')
        output = io.StringIO()
        with patch('sys.argv',['probe','--binary','fixture','--path','secret','--details']), \
             patch.object(Path,'resolve',return_value=Path('/fixture')), \
             patch.object(Path,'read_bytes',return_value=elf), \
             patch.object(TX.subprocess,'run',side_effect=runs), \
             patch.object(TX.GUARD,'inspect',return_value=(TX.GUARD.SYMBOL,list(range(31)))), \
             patch.object(TX,'body',return_value=metadata),redirect_stdout(output):
            self.assertEqual(TX.main(),0)
        self.assertIn('"observed_combined_bypass_rejected": true',output.getvalue())
        self.assertNotIn('KNOWN_IN_MODEL_ESCAPE',output.getvalue())
        self.assertIn('NOT complete C1/DC1/L1 or release qualification',output.getvalue())


if __name__ == '__main__':
    unittest.main()
