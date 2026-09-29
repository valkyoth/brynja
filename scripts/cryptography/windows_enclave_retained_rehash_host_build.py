#!/usr/bin/env python3
"""Private affine Pending.rehash integration for a separate composition image."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import windows_enclave_retained_borrowed_host_build as base

ROOT,SOURCE=base.ROOT,base.SOURCE
replace=base.replace
VARIANTS=base.VARIANTS
SOURCES=tuple(sorted(set(base.SOURCES)|{'assurance/windows-enclave-probe/retained_rehash_report.h',
    'scripts/cryptography/windows_enclave_retained_rehash_host_build.py',
    'scripts/cryptography/windows_enclave_retained_rehash_host_run.py',
    'scripts/cryptography/test-windows-enclave-retained-rehash-host.py'}))


def prepare(directory):
    base.prepare(directory)
    shutil.copyfile(SOURCE/'retained_rehash_report.h',directory/'retained_rehash_report.h')
    model=(directory/'retained_model.rs').read_text()
    model=replace(model,'        fn cancel(&mut self, generation: u64)',
                  '        fn rehash(&mut self, generation: u64) -> Result<Receipt, ()>;\n        fn cancel(&mut self, generation: u64)')
    model=replace(model,'    pub fn cancel(mut self) -> Result<(), Error> {',
                  '    pub fn rehash(mut self) -> Result<Self, Error> {\n'
                  '        self.armed = false; self.session.state = State::Quarantined;\n'
                  '        let receipt = self.session.driver.rehash(self.session.generation);\n'
                  '        if !self.session.check(receipt, Outcome::Ready) { return Err(Error::Protocol); }\n'
                  '        self.session.state = State::Busy; self.armed = true; Ok(self)\n    }\n'
                  '    pub fn cancel(mut self) -> Result<(), Error> {')
    (directory/'retained_model.rs').write_text(model)
    rust=(directory/'retained_native_host.rs').read_text()
    rust=replace(rust,'    fn cancel(&mut self, generation: u64)',
                 '    fn rehash(&mut self, generation: u64) -> Result<Receipt, ()> {\n'
                 '        if !self.live || generation != self.generation { return Err(()); }\n'
                 '        self.call(8, core::ptr::null_mut(), [8, 1, 0, 0])?;\n'
                 '        if self.fault == 6 { self.call(9, core::ptr::null_mut(), [8, 1, 0, 0])?; }\n'
                 '        Ok(self.receipt(generation, Outcome::Ready))\n    }\n'
                 '    fn cancel(&mut self, generation: u64)')
    (directory/'retained_native_host.rs').write_text(rust)
    campaign=(directory/'retained_native_campaign.rs').read_text()
    campaign=replace(campaign,'for (case, digest) in DIGESTS.iter().enumerate()',
                     'for (case, digest) in CHAINS.iter().enumerate()')
    campaign=replace(campaign,'        if pending.export_public(&mut output).is_err()',
                     '        let mut pending = pending;\n'
                     '        for _ in 0..(case % 4 + 1) { let Ok(next) = pending.rehash() else { return 60; }; pending = next; }\n'
                     '        if pending.export_public(&mut output).is_err()')
    campaign=replace(campaign,'        if pending.cancel().is_err()',
                     '        let Ok(pending) = pending.rehash() else { return 61; };\n        if pending.cancel().is_err()')
    campaign=replace(campaign,'        if forget {',
                     '        let Ok(pending) = pending.rehash() else { return 62; };\n        if forget {')
    campaign=replace(campaign,'    // Parent-only destruction also owns actual OS teardown.',
                     '    {\n        let Some(mut owner) = open(image, 6) else { return 63; };\n'
                     '        let Ok(pending) = owner.begin(MESSAGES[1]) else { return 64; };\n'
                     '        if !matches!(pending.rehash(), Err(Error::Protocol)) || owner.state() != State::Quarantined { return 65; }\n'
                     '        if owner.close().is_err() { return 66; }\n    }\n'
                     '    // Parent-only destruction also owns actual OS teardown.')
    # Preserve use of base DIGESTS for the mock ABI, without a dead-code allowance.
    campaign=replace(campaign,'\n    let before = unsafe { HostCounter(2) };',
                     '\n    if DIGESTS.len() != CHAINS.len() { return 67; }\n    let before = unsafe { HostCounter(2) };')
    (directory/'retained_native_campaign.rs').write_text(campaign)
    rows=['const CHAINS: [[u8;32];20] = [']
    for index,message in enumerate(base.base.vectors()):
        value=hashlib.sha256(message).digest()
        for _ in range(index%4+1):value=hashlib.sha256(value).digest()
        rows.append('['+','.join(map(str,value))+'],')
    with (directory/'retained_native_vectors.rs').open('a') as output:output.write('\n'.join(rows+['];','']))
    header=(directory/'native_host.h').read_text()
    header=replace(header,'input, input_control;','input, input_control, rehash_control;')
    header=replace(header,'uint64_t input_epoch;', 'uint64_t input_epoch, result_generation;')
    (directory/'native_host.h').write_text(header)
    resource=(directory/'native_host_resource.c').read_text()
    resource=replace(resource,'    if (!instance->output || !instance->input || !instance->input_control)',
                     '    instance->rehash_control = (LPENCLAVE_ROUTINE)GetProcAddress((HMODULE)instance->base, "PublicRehashControl");\n'
                     '    if (!instance->output || !instance->input || !instance->input_control || !instance->rehash_control)')
    (directory/'native_host_resource.c').write_text(resource)
    c=(directory/'retained_native_transport.c').read_text()
    c=replace(c,'#include "retained_input_report.h"','#include "retained_input_report.h"\n#include "retained_rehash_report.h"')
    c=replace(c,'    uint64_t input[11];','    uint64_t input[11], rehash[9];')
    c=replace(c,'    expected = op == 0 ?',
              '    for (i = 0; i < 9; ++i) { if (!HostCall(owner->rehash_control, i + 16, &rehash[i])) { return FALSE; } }\n'
              '    if (!retained_rehash_report(rehash, op, inner[0], call->low, call->low + 65536, owner->result_generation, owner->input_epoch)) { return FALSE; }\n'
              '    expected = op == 8 ? 8 : op == 9 ? 103 : op == 0 ?')
    c=replace(c,'inner[4] != (ULONG_PTR)(op == 1)', 'inner[4] != (ULONG_PTR)(op == 1 || op == 8 || op == 9)')
    c=replace(c,'    report[0] = inner[0];',
              '    if (op == 1 && inner[0] == 2) { owner->result_generation = 1; }\n'
              '    if (op == 8) { owner->result_generation += 1; } /* checked by report validator */\n'
              '    report[0] = inner[0];')
    c=replace(c,'(op > 4 && op != 6)', '(op > 4 && op != 6 && op != 8 && op != 9)')
    c=replace(c,'if (op == 0) { owner->input_epoch += 1; }',
              'if (op == 0) { owner->input_epoch += 1; owner->result_generation = 0; }')
    (directory/'retained_native_transport.c').write_text(c)
    main=(directory/'retained_native_main.c').read_text()
    main=replace(main,'HostCounter(2) == 160','HostCounter(2) == 230')
    main=replace(main,'HostCounter(0) == 9 && HostCounter(1) == 9 && HostCounter(2) == 184',
                 'HostCounter(0) == 10 && HostCounter(1) == 10 && HostCounter(2) == 261')
    (directory/'retained_native_main.c').write_text(main)


def build(directory):
    directory=directory.resolve();prepare(directory);commands=[]
    for name,cfg in VARIANTS.items():
        command=['rustc','+1.98.1','--edition=2024','--target','x86_64-pc-windows-msvc','--crate-type','staticlib',
                 '--crate-name','retained_rehash_host','-D','warnings','-C','opt-level=2','-C','panic=abort',
                 '-C','overflow-checks=yes',str(directory/'retained_native_host.rs'),'-o',str(directory/(name+'.lib'))]
        if cfg:command+=['--cfg',cfg]
        subprocess.run(command,check=True,capture_output=True,timeout=120);commands.append(command)
    record={'native_executed':False,'strict_qualified':False,'public_vectors_only':True,'commands':commands,
            'rustc':subprocess.check_output(['rustc','+1.98.1','-vV'],text=True),
            'source_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES},
            'generated_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.iterdir()) if p.suffix in ('.rs','.h','.c')},
            'archives':{n+'.lib':hashlib.sha256((directory/(n+'.lib')).read_bytes()).hexdigest() for n in VARIANTS}}
    (directory/'retained-rehash-host-build.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Retained rehash host cross-build: PASS; native qualification: NO')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path)
    build(parser.parse_args().directory)
