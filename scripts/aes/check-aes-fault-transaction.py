#!/usr/bin/env python3
"""Finite x86-64 integrated workbench observations, NOT release qualification.

Executes a trusted local test ELF under GDB hardware breakpoints. No code bytes
are patched. Public fixtures only; never supply an untrusted binary.
Zero exit means the finite declared observations reproduced, not complete
fault qualification. This is not a verification pass or a release gate.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location('guard_leaf', Path(__file__).with_name('check-aes-fault-guard.py'))
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)
PREFIX = 'brynja_crypto::aes::fault_integrity::transaction::'
ROOT = PREFIX+'probe_tests::public_call'
CHECK = PREFIX+'check'
TEST = 'aes::fault_integrity::transaction::probe_tests::native_public_transaction_probe'
SECRET_ROOT = PREFIX+'probe_tests::secret_call'
SECRET_TEST = 'aes::fault_integrity::transaction::probe_tests::native_secret_transaction_probe'
CASES = ('baseline', 'invalid-entry-state', 'state-after-write', 'output-after-write',
         'primary-after-write', 'output-plus-first-readback-bypass',
         'output-plus-second-readback-bypass', 'two-readbacks-bypass',
         'after-final-check-negative-control')
SECRET_CASES = CASES+('staging-after-write', 'combined-decision-bypass')


def body(dump, wanted):
    found, selected, instructions, symbol = False, False, [], None
    for line in dump.splitlines():
        header = re.fullmatch(r'\s*([0-9a-fA-F]+) <(.+)>:\s*',line)
        if header:
            selected = re.sub(r'::h[0-9a-f]{16}$','',header[2]) == wanted
            if selected:
                if found: raise ValueError('duplicate caller symbol')
                found, symbol, start = True, header[2], int(header[1],16)
        elif selected and line.strip():
            instruction = re.fullmatch(r'\s*([0-9a-fA-F]+):\s+(.+?)\s*',line)
            if not instruction: raise ValueError('unparsed caller instruction')
            instructions.append((int(instruction[1],16),re.sub(r'\s+',' ',instruction[2])))
    while instructions and instructions[-1][1] == 'int3': instructions.pop()
    addresses = [a for a,_ in instructions]
    if not found or not addresses or addresses[0] != start or addresses != sorted(set(addresses)):
        raise ValueError('missing/invalid caller')
    returns = [a-start for a,op in instructions if op == 'ret']
    if len(returns) != 1: raise ValueError('unreviewed return-site multiplicity')
    result = dict(symbol=symbol, ret=returns[0],
                  instructions_sha256=hashlib.sha256(repr(instructions).encode()).hexdigest())
    if wanted == SECRET_ROOT:
        # Explicit observed compiler pattern, not a generic branch classifier.
        # Fail closed if a new build changes or duplicates this decision site.
        legacy = [instructions[i+2][0]-start for i in range(len(instructions)-2)
                  if instructions[i][1] == 'or %al,%bpl'
                  and instructions[i+1][1] == 'mov $0x1,%r12b'
                  and instructions[i+2][1].startswith('jne ')]
        # The current linked caller branches on validate()'s combined R1/R2
        # result rather than emitting the earlier OR. Match the call and its
        # exact flag-setting sequence; never infer a convenient nearby jne.
        validated = [(instructions[i+3][0]-start, register) for i in range(len(instructions)-3)
                     for register in ('r12b', 'bpl')
                     if instructions[i][1].startswith('call ')
                     and instructions[i][1].endswith('<brynja_crypto::aes::fault_integrity::transaction::validate>')
                     and instructions[i+1][1] == f'mov $0x1,%{register}'
                     and instructions[i+2][1] == 'test %al,%al'
                     and instructions[i+3][1].startswith('jne ')]
        if len(legacy)+len(validated) != 1:
            raise ValueError('unreviewed combined decision site')
        result['combined_decision'] = legacy[0] if legacy else validated[0][0]
        result['combined_kind'] = 'legacy-or' if legacy else 'validate-'+validated[0][1]
    return result


def same_bytes(pointer, byte):
    # Observe all sixteen bytes, not a convenient matching prefix. Normal
    # program ABI is checked dynamically before any mutation is attempted.
    word = int.from_bytes(bytes([byte])*8,'little')
    return f'(*(unsigned long long*)({pointer}) == {word}ULL && *(unsigned long long*)(({pointer})+8) == {word}ULL)'


def commands(case, root, check, guard_symbol, guard_offsets):
    if case not in CASES: raise ValueError('unknown experiment')
    entry = case == 'invalid-entry-state'
    late = case == 'after-final-check-negative-control'
    bypass = 'readback' in case
    result = ['set debuginfod enabled off','set pagination off','set disable-randomization off',
              'starti','set language c',f"hbreak *'{root['symbol']}'"]
    if not entry:
        result.append(f"hbreak *('{guard_symbol}'+{guard_offsets[24]})")
    if bypass:
        result.append(f"hbreak *('{check['symbol']}'+{check['ret']})")
        if case == 'output-plus-second-readback-bypass': result.append('ignore 3 1')
    elif late:
        result.append(f"hbreak *('{root['symbol']}'+{root['ret']})")
    result += ['continue','set $owner=(unsigned char*)$rdi','set $destination=(unsigned char*)$rsi',
               f'printf "TX_ENTRY %d\\n", ({same_bytes("$owner",0xa5)} && {same_bytes("$destination",0x91)} && $owner != $destination)',
               'disable 1']
    if entry:
        result += ['set *$owner = *$owner ^ 1','printf "TX_MUTATED %d\\n", (*$owner == 0xa4)']
    else:
        result += ['continue','set $primary=(unsigned char*)$rsi',
                   f'printf "TX_COPY %d\\n", ({same_bytes("$owner",0x3c)} && {same_bytes("$destination",0x42)} && {same_bytes("$primary",0x42)} && (unsigned char*)$rdi == $destination)',
                   'disable 2']
        if case == 'state-after-write': target, expected = '$owner',0x3d
        elif case == 'primary-after-write': target, expected = '$primary',0x43
        elif case == 'output-after-write' or bypass: target, expected = '$destination',0x43
        else: target = None
        if target:
            result += [f'set *{target} = *{target} ^ 1', f'printf "TX_MUTATED %d\\n", (*{target} == {expected})']
    if bypass:
        count = 2 if case == 'two-readbacks-bypass' else 1
        for _ in range(count):
            result += ['continue','printf "TX_CHECK_FAILED %d\\n", ($al == 1)',
                       'set $al = $al ^ 1','printf "TX_BYPASSED %d\\n", ($al == 0)']
        result.append('disable 3')
    elif late:
        result += ['continue',f'printf "TX_LATE %d\\n", ({same_bytes("$owner",0xa5)} && {same_bytes("$destination",0x42)} && $al == 0)',
                   'set *$destination = *$destination ^ 1','printf "TX_MUTATED %d\\n", (*$destination == 0x43)', 'disable 3']
    return result+['continue']


def secret_commands(case, root, check, guard_symbol, guard_offsets):
    if case not in SECRET_CASES: raise ValueError('unknown experiment')
    entry = case == 'invalid-entry-state'
    staging = case == 'staging-after-write'
    late = case == 'after-final-check-negative-control'
    bypass = 'readback' in case
    combined = case == 'combined-decision-bypass'
    result = ['set debuginfod enabled off','set pagination off','set disable-randomization off',
              'starti','set language c',f"hbreak *'{root['symbol']}'"]
    if staging:
        result.append(f"hbreak *('{guard_symbol}'+{guard_offsets[24]})")
    elif not entry:
        # The first two calls check private staging. Stop at the third, which
        # checks the actual admitted destination AFTER initialization.write.
        result += [f"hbreak *'{check['symbol']}'", 'ignore 2 2']
    if bypass:
        result += [f"hbreak *('{check['symbol']}'+{check['ret']})", 'disable 3']
    elif late:
        result.append(f"hbreak *('{root['symbol']}'+{root['ret']})")
    elif combined:
        result.append(f"hbreak *('{root['symbol']}'+{root['combined_decision']})")
    result += ['continue','set $result=(unsigned char*)$rdi',
               'set $owner=(unsigned char*)$rsi','set $destination=(unsigned char*)$rdx',
               f'printf "TX_ENTRY %d\\n", ({same_bytes("$owner",0xa5)} && {same_bytes("$destination",0x91)} && $owner != $destination && $result != $owner && $result != $destination)',
               'disable 1']
    if entry:
        result += ['set *$owner = *$owner ^ 1','printf "TX_MUTATED %d\\n", (*$owner == 0xa4)']
    elif staging:
        result += ['continue','set $staging=(unsigned char*)$rdi',
                   f'printf "TX_STAGING %d\\n", ({same_bytes("$owner",0x3c)} && {same_bytes("$destination",0)} && {same_bytes("$staging",0x42)} && $staging != $destination)',
                   'set *$staging = *$staging ^ 1',
                   'printf "TX_MUTATED %d\\n", (*$staging == 0x43)', 'disable 2']
    else:
        result += ['continue','set $primary=(unsigned char*)$rdx',
                   'set $secondary=(unsigned char*)$rcx',
                   f'printf "TX_COPY %d\\n", ({same_bytes("$owner",0x3c)} && {same_bytes("$destination",0x42)} && {same_bytes("$primary",0x42)} && {same_bytes("$secondary",0x42)} && (unsigned char*)$rdi == $destination && $rsi == 16 && ($r8 & 255) == 0 && $primary != $destination && $secondary != $destination && $primary != $secondary)',
                   'disable 2']
        if case == 'state-after-write': target, expected = '$owner',0x3d
        elif case == 'primary-after-write': target, expected = '$primary',0x43
        elif case == 'output-after-write' or bypass or combined: target, expected = '$destination',0x43
        else: target = None
        if target:
            result += [f'set *{target} = *{target} ^ 1', f'printf "TX_MUTATED %d\\n", (*{target} == {expected})']
    if bypass:
        result.append('enable 3')
        if case == 'output-plus-second-readback-bypass': result.append('ignore 3 1')
        count = 2 if case == 'two-readbacks-bypass' else 1
        for _ in range(count):
            result += ['continue','printf "TX_CHECK_FAILED %d\\n", ($al == 1)',
                       'set $al = $al ^ 1','printf "TX_BYPASSED %d\\n", ($al == 0)']
        result.append('disable 3')
    elif late:
        result += ['continue',f'printf "TX_LATE %d\\n", ({same_bytes("$owner",0xa5)} && {same_bytes("$destination",0x42)} && *(unsigned long long*)$result == 0 && *(unsigned char**)($result+8) == $destination && *(unsigned long long*)($result+16) == 16)',
                   'set *$destination = *$destination ^ 1','printf "TX_MUTATED %d\\n", (*$destination == 0x43)', 'disable 3']
    elif combined:
        # Preserve the original failure injection; the fresh permit must now
        # reject even when this earlier shared decision is bypassed.
        kind = root.get('combined_kind')
        if kind in ('legacy-or', 'validate-bpl'):
            decision = '($al == 1 && $bpl == 1 && ($eflags & 64) == 0)'
        elif kind == 'validate-r12b':
            decision = '($al == 1 && ($r12 & 255) == 1 && ($eflags & 64) == 0)'
        else:
            raise ValueError('unreviewed combined decision kind')
        result += ['continue',f'printf "TX_COMBINED_FAILED %d\\n", {decision}',
                   'set $eflags = $eflags ^ 64',
                   'printf "TX_COMBINED_BYPASSED %d\\n", (($eflags & 64) != 0)', 'disable 3']
    return result+['continue']


def validate(text, case, path='public'):
    if path not in ('public','secret'): raise ValueError('unknown path')
    secret = path == 'secret'
    if case not in (SECRET_CASES if secret else CASES): raise ValueError('unknown experiment')
    entry = case == 'invalid-entry-state'
    staging = case == 'staging-after-write'
    combined = int(case == 'combined-decision-bypass')
    negative = case.endswith('negative-control')
    bypasses = 2 if case == 'two-readbacks-bypass' else int('readback' in case)
    late = int(case == 'after-final-check-negative-control')
    markers = {'TX_ENTRY':1, 'TX_COPY':int(not entry and not staging), 'TX_STAGING':int(staging), 'TX_MUTATED':int(case != 'baseline'),
               'TX_CHECK_FAILED':bypasses,'TX_BYPASSED':bypasses,'TX_LATE':late,
               'TX_COMBINED_FAILED':combined,'TX_COMBINED_BYPASSED':combined}
    for marker,count in markers.items():
        if re.findall(r'(?m)^'+marker+r' (\d+)$',text) != ['1']*count:
            raise ValueError('missing/incorrect checkpoint: '+marker)
    stops = 1+int(not entry)+bypasses+late+combined
    breakpoints = 1+int(not entry)+int(bool(bypasses or late or combined))
    if len(re.findall(r'hit Breakpoint \d+,',text)) != stops or text.count('Hardware assisted breakpoint ') != breakpoints:
        raise ValueError('hardware stop count not confirmed')
    if (SECRET_TEST if secret else TEST) not in text or 'BRYNJA_TRANSACTION_EVIDENCE_CFG=false' not in text or 'BRYNJA_TRANSACTION_EVIDENCE_CFG=true' in text:
        raise ValueError('wrong fixture or source-instrumented artifact')
    if negative:
        markers = ['test result: FAILED. 0 passed; 1 failed; 0 ignored;',
                   'left: [67, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66]',
                   'exited with code 0145']
    else:
        accepted = 'BRYNJA_SECRET_ACCEPTED_CLEARED' if secret else 'BRYNJA_TRANSACTION_ACCEPTED'
        rejected = 'BRYNJA_SECRET_REJECTED_CLEARED_RETIRED' if secret else 'BRYNJA_TRANSACTION_REJECTED_RESTORED_RETIRED'
        outcome, other = (accepted,rejected) if case == 'baseline' else (rejected,accepted)
        if other in text: raise ValueError('wrong transaction outcome')
        markers = [outcome,'test result: ok. 1 passed; 0 failed; 0 ignored;','exited normally']
    if any(marker not in text for marker in markers): raise ValueError('unconfirmed fixture outcome (required status or exit marker missing)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--path',choices=('public','secret'),default='public')
    parser.add_argument('--details',action='store_true',help='also print a JSON status and completed case count on success')
    parser.add_argument('--objdump',default='objdump')
    parser.add_argument('--gdb',default='gdb')
    args = parser.parse_args()
    completed = 0
    try:
        binary = args.binary.resolve(strict=True)
        original = binary.read_bytes()
        if original[:6] != b'\x7fELF\x02\x01' or original[18:20] != b'\x3e\x00':
            raise ValueError('requires x86-64 little-endian ELF')
        dump = subprocess.run([args.objdump,'-d','--demangle','--no-show-raw-insn',str(binary)],
                              capture_output=True,text=True,check=True,timeout=30).stdout
        guard_symbol, guard_offsets = GUARD.inspect(dump)
        if args.path == 'public':
            cases, command_builder, root_name, test_name = CASES, commands, ROOT, TEST
        else:
            cases, command_builder, root_name, test_name = SECRET_CASES, secret_commands, SECRET_ROOT, SECRET_TEST
        root, check = body(dump,root_name),body(dump,CHECK)
        for case in cases:
            argv = [args.gdb,'-q','-nx','-batch']
            for command in command_builder(case,root,check,guard_symbol,guard_offsets): argv += ['-ex',command]
            argv += ['--args',str(binary),'--exact',test_name,'--nocapture']
            run = subprocess.run(argv,capture_output=True,text=True,check=True,timeout=60)
            transcript = run.stdout+run.stderr
            validate(transcript,case,args.path)
            completed += 1
        if binary.read_bytes() != original: raise ValueError('artifact changed during experiment')
        if args.details:
            print(json.dumps({'status': 'pass', 'completed': completed},sort_keys=True))
        print(f'{completed} declared experiment outcomes reproduced')
        print('DEVELOPMENT_TRANSACTION_OBSERVED; NOT complete C1/DC1/L1 or release qualification')
        return 0
    except (OSError,ValueError,subprocess.SubprocessError):
        # Exception text can contain tool output; report only validated progress.
        print(f'transaction experiment failed after {completed} completed cases',file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
