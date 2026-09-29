#!/usr/bin/env python3
"""Compose private affine Rust host with the separately reviewed input image."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import windows_enclave_retained_native_host_build as base

ROOT,SOURCE=base.ROOT,base.SOURCE
replace=base.replace
VARIANTS=base.VARIANTS
SOURCES=tuple(sorted(set(base.SOURCES)|{
    'assurance/windows-enclave-probe/retained_input.rs',
    'assurance/windows-enclave-probe/retained_input_report.h',
    'scripts/cryptography/windows_enclave_retained_borrowed_host_build.py',
    'scripts/cryptography/windows_enclave_retained_borrowed_host_run.py',
    'scripts/cryptography/test-windows-enclave-retained-borrowed-host.py',
}))


def prepare(directory):
    base.prepare(directory)
    shutil.copyfile(SOURCE/'retained_input_report.h',directory/'retained_input_report.h')
    (directory/'retained_input.rs').write_text(replace((SOURCE/'retained_input.rs').read_text(),'#![no_std]\n',''))
    model=(directory/'retained_model.rs').read_text()
    start=model.index('/// A selector for one of');end=model.index('pub struct Session',start)
    model=model[:start]+model[end:]
    model=replace(model,'fn begin(&mut self, vector: u8, generation: u64)',
                  'fn begin(&mut self, request: &crate::retained_input::Request<\'_>, generation: u64)')
    model=replace(model,'pub fn begin(&mut self, vector: PublicVector)', 'pub fn begin(&mut self, input: &[u8])')
    model=replace(model,'        // Arm fail-closed state BEFORE either arithmetic or foreign entry.',
                  '        if input.len() > crate::retained_input::CAPACITY { return Err(Error::Bounds); }\n'
                  '        // Arm fail-closed state BEFORE either arithmetic or foreign entry.')
    model=replace(model,'        self.generation = next;\n        let receipt = self.driver.begin(vector.0, next);',
                  '        let request = crate::retained_input::Request::new(input, next).map_err(|_| Error::Bounds)?;\n'
                  '        self.generation = next;\n        let receipt = self.driver.begin(&request, next);')
    (directory/'retained_model.rs').write_text(model)
    rust=(directory/'retained_native_host.rs').read_text()
    rust=replace(rust,'//! Private native adapter for fixed PUBLIC vectors. Not a shipped backend.',
                 '//! Private borrowed-input native adapter. Research only, not a shipped backend.')
    rust=replace(rust,'mod retained_model;','mod retained_model;\nmod retained_input;')
    rust=replace(rust,'Error, PublicVector, Session, State','Error, Session, State')
    rust=replace(rust,'fn RetainedRun(','fn RetainedInputRun(')
    rust=replace(rust,'        operation: u64,\n        output: *mut u8,',
                 '        operation: u64,\n        input: *const u8,\n        output: *mut u8,')
    rust=replace(rust,'    fn call(&mut self, operation: u64, output: *mut u8, expected: [u64; 4]) -> Result<(), ()> {',
                 '    fn call(&mut self, operation: u64, output: *mut u8, expected: [u64; 4]) -> Result<(), ()> {\n'
                 '        self.call_input(operation, core::ptr::null(), output, expected)\n    }\n'
                 '    fn call_input(&mut self, operation: u64, input: *const u8, output: *mut u8, expected: [u64; 4]) -> Result<(), ()> {')
    rust=replace(rust,'RetainedRun(pointer.as_ptr(), operation, output, &mut report)',
                 'RetainedInputRun(pointer.as_ptr(), operation, input, output, &mut report)')
    rust=replace(rust,'    fn begin(&mut self, vector: u8, generation: u64)',
                 '    fn begin(&mut self, request: &retained_input::Request<\'_>, generation: u64)')
    rust=replace(rust,'self.live || vector >= 20 ||','self.live ||')
    rust=replace(rust,'        // Assume responsibility BEFORE entry, including a lost creation reply.',
                 '        retained_input::admit(request.metadata(), generation).map_err(|_| ())?;\n'
                 '        // Assume responsibility BEFORE entry, including a lost creation reply.')
    rust=replace(rust,'        self.call(\n            1 | (u64::from(vector) << 8),\n            core::ptr::null_mut(),\n            [2, 1, 0, 0],\n        )?;',
                 '        // Request and original input remain borrowed until this synchronous call returns.\n'
                 '        // These two PRIVATE diagnostic modes corrupt metadata, never the public request.\n'
                 '        if self.fault == 4 || self.fault == 5 {\n'
                 '            let mut header = *request.metadata();\n'
                 '            if self.fault == 4 { header[8..16].copy_from_slice(&0u64.to_le_bytes()); }\n'
                 '            else { header[24..32].copy_from_slice(&1u64.to_le_bytes()); }\n'
                 '            self.call_input(1, header.as_ptr(), core::ptr::null_mut(), [2, 1, 0, 0])?;\n'
                 '        } else {\n'
                 '            self.call_input(1, request.metadata().as_ptr(), core::ptr::null_mut(), [2, 1, 0, 0])?;\n'
                 '        }')
    (directory/'retained_native_host.rs').write_text(rust)
    campaign=(directory/'retained_native_campaign.rs').read_text()
    campaign=campaign.replace('PublicVector::new(case as u8).unwrap()','MESSAGES[case]').replace('PublicVector::new(1).unwrap()','MESSAGES[1]')
    campaign=replace(campaign,'owner.begin(MESSAGES[case]) else {\n            return 11;',
                     'owner.begin(&temporary[..MESSAGES[case].len()]) else {\n            return 11;')
    campaign=replace(campaign,'        let mut output = [0xcc; 32];\n        let Ok(pending) = owner.begin(&temporary',
                     '        let mut temporary = [0; 1024];\n        temporary[..MESSAGES[case].len()].copy_from_slice(MESSAGES[case]);\n'
                     '        let mut output = [0xcc; 32];\n        let Ok(pending) = owner.begin(&temporary')
    campaign=replace(campaign,'        if pending.export_public(&mut output).is_err()',
                     '        temporary.fill(0); // Input borrow ended; retained digest must not depend on it.\n'
                     '        if pending.export_public(&mut output).is_err()')
    campaign=replace(campaign,'    // Parent-only destruction also owns actual OS teardown.',
                     '    for fault in [4, 5] {\n'
                     '        let Some(mut owner) = open(image, fault) else { return 50; };\n'
                     '        if owner.begin(MESSAGES[1]).is_ok() || owner.state() != State::Quarantined { return 51; }\n'
                     '        if owner.close().is_err() { return 52; }\n    }\n'
                     '    // Parent-only destruction also owns actual OS teardown.')
    campaign=replace(campaign,'    for (case, digest) in DIGESTS.iter().enumerate() {',
                     '    let before = unsafe { HostCounter(2) };\n'
                     '    if !matches!(owner.begin(&[0; 1025]), Err(Error::Bounds)) || owner.state() != State::Ready\n'
                     '        || unsafe { HostCounter(2) } != before { return 53; }\n'
                     '    for (case, digest) in DIGESTS.iter().enumerate() {')
    (directory/'retained_native_campaign.rs').write_text(campaign)
    with (directory/'retained_native_vectors.rs').open('a') as output:
        output.write('const MESSAGES: [&[u8];20] = [\n'+''.join('&['+','.join(map(str,v))+'],\n' for v in base.vectors())+'];\n')
    prepare_c(directory)


def prepare_c(directory):
    header=(directory/'native_host.h').read_text()
    header=replace(header,'control, guard, output;', 'control, guard, output, input, input_control;\n    uint64_t input_epoch;')
    (directory/'native_host.h').write_text(header)
    resource=(directory/'native_host_resource.c').read_text()
    resource=replace(resource,'    if (!instance->output) { goto failed; }',
                     '    instance->input = (LPENCLAVE_ROUTINE)GetProcAddress((HMODULE)instance->base, "PublicRetainedInput");\n'
                     '    instance->input_control = (LPENCLAVE_ROUTINE)GetProcAddress((HMODULE)instance->base, "PublicInputControl");\n'
                     '    if (!instance->output || !instance->input || !instance->input_control) { goto failed; }')
    (directory/'native_host_resource.c').write_text(resource)
    source=(directory/'retained_native_transport.c').read_text()
    source=replace(source,'/* Fixed PUBLIC vectors only. No application callbacks or confidential host data. */',
                   '/* Private synchronous borrowed-input transport; PUBLIC test vectors only. */')
    source=replace(source,'#include "retained_page_admission.h"', '#include "retained_page_admission.h"\n#include "retained_input_report.h"')
    source=replace(source,'    ULONG_PTR low, operation;', '    ULONG_PTR low, operation;\n    uint64_t input_length;')
    source=replace(source,'    ULONG_PTR outer[7], guards[13], inner[10];', '    ULONG_PTR outer[7], guards[13], inner[10];\n    uint64_t input[11];')
    source=replace(source,'    expected = op == 0 ? 1 : op == 1 ? 2 :',
                   '    for (i = 0; i < 11; ++i) { if (!HostCall(owner->input_control, i + 16, &input[i])) { return FALSE; } }\n'
                   '    if (!retained_input_report(input, op, inner[0], call->low, call->low + 65536, call->input_length, owner->input_epoch)) { return FALSE; }\n'
                   '    expected = op == 0 ? 1 : op == 1 ? (inner[0] == 120 || inner[0] == 121 ? inner[0] : 2) :')
    source=replace(source,'int RetainedRun(void* opaque, uint64_t operation, unsigned char* output, uint64_t* report)',
                   'int RetainedInputRun(void* opaque, uint64_t operation, const unsigned char* input, unsigned char* output, uint64_t* report)')
    source=replace(source,'operation >> 8 > 19 ||','operation >> 8 || ((op == 1) != (input != NULL)) || (op == 0 && owner->input_epoch == UINT64_MAX) ||')
    source=replace(source,'    owner->busy = TRUE;',
                   '    owner->busy = TRUE;\n'
                   '    if (op == 0) { owner->input_epoch += 1; }\n'
                   '    if (input) { memcpy(&call.input_length, input + 16, sizeof(call.input_length)); }')
    source=replace(source,'    if (!HostCall(owner->output, (ULONG_PTR)output, &result)',
                   '    if (!HostCall(owner->input, (ULONG_PTR)input, &result) || result != 1) { goto done; }\n'
                   '    if (!HostCall(owner->output, (ULONG_PTR)output, &result)')
    source=replace(source,'    current = NULL;',
                   '    if (!HostCall(owner->input, 0, &removed) || removed != 1) { ok = FALSE; }\n    current = NULL;')
    (directory/'retained_native_transport.c').write_text(source)
    main=(directory/'retained_native_main.c').read_text()
    main=replace(main,'HostCounter(0) == 7 && HostCounter(1) == 7 && HostCounter(2) == 178',
                 'HostCounter(0) == 9 && HostCounter(1) == 9 && HostCounter(2) == 184')
    (directory/'retained_native_main.c').write_text(main)


def build(directory):
    directory=directory.resolve();prepare(directory);commands=[]
    for name,cfg in VARIANTS.items():
        command=['rustc','+1.98.1','--edition=2024','--target','x86_64-pc-windows-msvc',
                 '--crate-type','staticlib','--crate-name','retained_borrowed_host','-D','warnings',
                 '-C','opt-level=2','-C','panic=abort','-C','overflow-checks=yes',
                 str(directory/'retained_native_host.rs'),'-o',str(directory/(name+'.lib'))]
        if cfg: command+=['--cfg',cfg]
        subprocess.run(command,check=True,capture_output=True,timeout=120);commands.append(command)
    generated=tuple(p.name for p in directory.iterdir() if p.suffix in ('.rs','.c','.h'))
    record={'native_executed':False,'strict_qualified':False,'public_vectors_only':True,'commands':commands,
            'rustc':subprocess.check_output(['rustc','+1.98.1','-vV'],text=True),
            'source_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES},
            'generated_sha256':{p:hashlib.sha256((directory/p).read_bytes()).hexdigest() for p in sorted(generated)},
            'archives':{n+'.lib':hashlib.sha256((directory/(n+'.lib')).read_bytes()).hexdigest() for n in VARIANTS}}
    (directory/'retained-borrowed-host-build.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Borrowed retained host cross-build: PASS; native execution/strict qualification: NO')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path)
    build(parser.parse_args().directory)
