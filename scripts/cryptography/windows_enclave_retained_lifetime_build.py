#!/usr/bin/env python3
"""Host lifetime/receipt IDs, separate from development image qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import windows_enclave_retained_rehash_host_build as base

ROOT,SOURCE,replace = base.ROOT,base.SOURCE,base.replace
VARIANTS = dict(base.VARIANTS, recycled='probe_retained_recycled_identity')
SOURCES = tuple(sorted(set(base.SOURCES)|{
    'assurance/windows-enclave-probe/retained_instance_id.rs',
    'scripts/cryptography/windows_enclave_retained_lifetime_build.py',
    'scripts/cryptography/windows_enclave_retained_lifetime_run.py',
    'scripts/cryptography/windows_enclave_retained_partial_run.py',
    'scripts/cryptography/test-windows-enclave-retained-lifetime.py'}))


def prepare(directory):
    base.prepare(directory)
    shutil.copyfile(SOURCE/'retained_instance_id.rs',directory/'retained_instance_id.rs')
    model=directory/'retained_model.rs'
    model.write_text(replace(model.read_text(),'    pub fn state(&self) -> State {',
        '    pub(crate) fn instance_id(&self) -> u64 { self.identity.get() }\n\n    pub fn state(&self) -> State {'))
    path=directory/'retained_native_host.rs';source=path.read_text()
    source=replace(source,'mod retained_model;','mod retained_model;\nmod retained_instance_id;')
    source=replace(source,'    // SAFETY: bounded live NUL-terminated path, native constructor is synchronous.',
        '    // Consume the ID BEFORE acquisition; failed construction must never recycle it.\n'
        '    let identity = if cfg!(probe_retained_recycled_identity) { NonZeroU64::new(1)? }\n'
        '        else { retained_instance_id::reserve()? };\n'
        '    // SAFETY: bounded live NUL-terminated path, native constructor is synchronous.')
    source=replace(source,'    // Private routing identity; never supplied as authority by a public caller.\n'
        '    let identity = NonZeroU64::new(pointer.as_ptr().addr() as u64)?;',
        '    // Identity is private process-local routing metadata, independent of allocation address.')
    source=replace(source,'        Ok(receipt)\n    }\n    fn rehash',
        '        if self.fault == 7 { receipt.identity = self.identity.get().saturating_sub(1); }\n'
        '        Ok(receipt)\n    }\n    fn rehash')
    path.write_text(source)
    path=directory/'retained_native_campaign.rs';source=path.read_text()
    source=replace(source,'    // Parent-only destruction also owns actual OS teardown.', '''
    {
        let Some(mut retired) = open(image, 0) else { return 68; };
        let previous = retired.instance_id();
        if retired.close().is_err() { return 69; }
        drop(retired);
        let Some(mut replacement) = open(image, 7) else { return 68; };
        if replacement.instance_id() <= previous { return 70; }
        let mut output = [0xcc;32];
        let Ok(pending) = replacement.begin(MESSAGES[1]) else { return 71; };
        if pending.export_public(&mut output) != Err(Error::Protocol) || output != [0xcc;32]
            || replacement.state() != State::Quarantined { return 72; }
        if replacement.close().is_err() { return 73; }
    }
    // Parent-only destruction also owns actual OS teardown.''')
    path.write_text(source)
    path=directory/'retained_native_main.c'
    path.write_text(replace(path.read_text(),
        'HostCounter(0) == 10 && HostCounter(1) == 10 && HostCounter(2) == 261',
        'HostCounter(0) == 12 && HostCounter(1) == 12 && HostCounter(2) == 265'))


def build(directory):
    directory=directory.resolve();prepare(directory);commands=[]
    for name,cfg in VARIANTS.items():
        command=['rustc','+1.98.1','--edition=2024','--target','x86_64-pc-windows-msvc','--crate-type','staticlib',
            '--crate-name','retained_lifetime_host','-D','warnings','-C','opt-level=2','-C','panic=abort',
            '-C','overflow-checks=yes',str(directory/'retained_native_host.rs'),'-o',str(directory/(name+'.lib'))]
        if cfg:command+=['--cfg',cfg]
        subprocess.run(command,check=True,capture_output=True,timeout=120);commands.append(command)
    record={'native_executed':False,'strict_qualified':False,'public_vectors_only':True,'commands':commands,
        'rustc':subprocess.check_output(['rustc','+1.98.1','-vV'],text=True),
        'source_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES},
        'generated_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(directory.iterdir()) if p.suffix in ('.rs','.c','.h')},
        'archives':{n+'.lib':hashlib.sha256((directory/(n+'.lib')).read_bytes()).hexdigest() for n in VARIANTS}}
    (directory/'retained-lifetime-build.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Nonrecycled host identity Windows cross-build: PASS; native qualification: NO')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path)
    build(parser.parse_args().directory)
