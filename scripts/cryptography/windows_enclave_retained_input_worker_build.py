#!/usr/bin/env python3
"""Build a separate borrowed-input retained worker; preserve earlier images."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import windows_enclave_retained_borrowed_build as model
import windows_enclave_retained_worker_build as previous

ROOT,SOURCE=model.ROOT,model.SOURCE
VARIANTS={'normal':None,'clear':'probe_retained_input_skip_clear','copy':'probe_retained_input_ignore_copy',
          'reread':'probe_retained_input_reread','sequence':'probe_retained_input_trust_header'}
FILES=('window_retained_borrowed.c','retained_borrowed_worker.rs','retained_borrowed_worker_tests.rs')
SOURCES=tuple(sorted(set(model.SOURCES)|set(previous.SOURCES)|{
    'assurance/windows-enclave-probe/'+n for n in FILES
}|{'scripts/cryptography/windows_enclave_retained_input_worker_build.py',
   'scripts/cryptography/test-windows-enclave-retained-input-worker.py',
   'scripts/cryptography/test-windows-enclave-retained-input-native.py',
   'scripts/cryptography/windows_enclave_retained_input_native.py'}))


def replace(source,before,after):
    if source.count(before)!=1: raise ValueError('retained input source anchor absent/ambiguous: '+before[:60])
    return source.replace(before,after,1)


def prepare(directory,target,testing=False):
    commands,_=model.prepare(directory,target,testing)
    for name in FILES: shutil.copyfile(SOURCE/name,directory/name)
    for name in ('window_retained.c','window_guard.c','window_lock.c','synthetic.c','window_rust_x64.asm'):
        shutil.copyfile(SOURCE/name,directory/name)
    source=(SOURCE/'window_retained.rs').read_text()
    begin=source.index('fn fill(case:'); end=source.index('/// # Safety')
    if source[begin:end].count('fn hash(')!=1 or source[begin:end].count('#[cfg(test)]')!=1:
        raise ValueError('unexpected original retained hash/test section')
    source=source[:begin]+'mod retained_borrowed_worker;\nuse retained_borrowed_worker::hash;\n\n'+source[end:]
    source=replace(source,'hash(owner, operation >> 8, low, high)',
                   'hash(owner, unsafe { EPOCH }, low, high)')
    (directory/'retained_input_worker.rs').write_text(source)
    tests=directory/'retained_borrowed_worker_tests.rs'
    rows=['#[test]','fn oracle_copies_header_once_and_retains_correct_digest() {']
    for message in model.base.base.base.vectors():
        rows.append('oracle(&['+','.join(map(str,message))+'], &['+
                    ','.join(map(str,hashlib.sha256(message).digest()))+']);')
    tests.write_text(tests.read_text()+'\n'+'\n'.join(rows+['}','']))
    return commands


def compile(directory,target,level='2',testing=False,variant='normal'):
    cfg=VARIANTS[variant]
    commands=[] if testing else model.compile(directory,target,level,testing=False,cfg=cfg)
    # A --test root requires unwind-compatible dependencies for copy-seam tests.
    if testing:
        commands=[]
        invocation=model.common(directory,target,level,True)
        for name,source in [('retained_input','retained_input.rs'),('retained_borrowed','retained_borrowed_digest.rs')]:
            command=invocation+['--crate-name',name,'--crate-type','rlib',str(directory/source),'-o',str(directory/('lib'+name+'.rlib'))]
            if name=='retained_borrowed':
                command+=['--extern','retained_input='+str(directory/'libretained_input.rlib')]
                if cfg: command+=['--cfg',cfg]
            subprocess.run(command,check=True,capture_output=True,timeout=90); commands.append(command)
    command=model.common(directory,target,level,testing)+['--crate-name','retained_input_worker',
        '--extern','retained_input='+str(directory/'libretained_input.rlib'),
        '--extern','retained_borrowed='+str(directory/'libretained_borrowed.rlib'),str(directory/'retained_input_worker.rs')]
    if testing:
        command+=['--test','-o',str(directory/(variant+'-test'))]
    else:
        command+=['--crate-type','staticlib','-C','lto=fat','--emit='+','.join(
            kind+'='+str(directory/(variant+'_rust.'+ext)) for kind,ext in [('link','lib'),('asm','s'),('llvm-ir','ll')])]
    if cfg: command+=['--cfg',cfg]
    subprocess.run(command,check=True,capture_output=True,timeout=120); commands.append(command)
    return commands


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path)
    directory=parser.parse_args().directory.resolve();target='x86_64-pc-windows-msvc'
    commands=prepare(directory,target)
    for name in VARIANTS: commands+=compile(directory,target,variant=name)
    record={'native_executed':False,'strict_qualified':False,'commands':commands,
            'source_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES},
            'rustc':subprocess.check_output(['rustc','+1.98.1','-vV'],text=True),
            'generated_source_sha256':hashlib.sha256((directory/'retained_input_worker.rs').read_bytes()).hexdigest(),
            'archives':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.glob('*_rust.lib'))}}
    (directory/'retained-input-worker-build.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Retained input worker Windows cross-build: PASS; native execution/strict qualification: NO')
