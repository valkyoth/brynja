#!/usr/bin/env python3
"""Borrowed-input/retained-owner composition; not native execution evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import windows_enclave_placement_build as placement
import windows_enclave_hardened_build as hardened

base=placement.base
ROOT,SOURCE=base.ROOT,base.SOURCE
FILES=('retained_input.rs','retained_borrowed_digest.rs','retained_borrowed_digest_tests.rs')
SOURCES=tuple(sorted(set(base.SOURCES)|{
    'assurance/windows-enclave-probe/'+p for p in FILES+('retained_placement.rs',)
}|{'scripts/cryptography/windows_enclave_retained_borrowed_build.py',
   'scripts/cryptography/test-windows-enclave-retained-borrowed.py',
   'scripts/cryptography/windows_enclave_placement_build.py',
   'scripts/cryptography/windows_enclave_hardened_build.py'}))
VARIANTS={'normal':None,'clear':'probe_retained_input_skip_clear','copy':'probe_retained_input_ignore_copy',
          'reread':'probe_retained_input_reread','width':'probe_retained_input_full_width',
          'quarantine':'probe_retained_input_no_quarantine'}


def prepare(directory,target,testing=False):
    hardened.layout_check()
    commands=base.build(directory,target,panic='unwind' if testing else 'abort')
    for name in FILES+('retained_placement.rs',):
        shutil.copyfile(SOURCE/name,directory/name)
    command=placement.command(directory,target,'2',False)
    if testing:
        command=[part.replace('panic=abort','panic=unwind') for part in command]
    subprocess.run(command,check=True,capture_output=True,timeout=90)
    commands.append(command)
    tests=directory/'retained_borrowed_digest_tests.rs'
    rows=['#[test]','fn independent_vectors_survive_scratch_return_and_copy_only_once() {']
    vectors=base.base.base.vectors()
    # Include every byte length through two block boundaries, then larger tails.
    vectors += [bytes((i*29+length)%256 for i in range(length)) for length in range(130)]
    for message in vectors:
        rows.append('oracle(&['+','.join(map(str,message))+'], &['+
                    ','.join(map(str,hashlib.sha256(message).digest()))+']);')
    tests.write_text(tests.read_text()+'\n'+'\n'.join(rows+['}','']))
    return commands,len(vectors)


def common(directory,target,level,testing):
    command=['rustc','+1.98.1','--edition=2024','--target',target,'-D','warnings',
             '-C','opt-level='+level,'-C','overflow-checks=yes',
             '-C','panic='+('unwind' if testing else 'abort'),'-L','dependency='+str(directory)]
    for name,filename in (('brynja_core','libbrynja_core.rlib'),
                          ('brynja_hash_sha2','libbrynja_hash_sha2.rlib'),
                          ('persistent_result','libpersistent_result_normal.rlib'),
                          ('retained_placement','libretained_placement.rlib')):
        command+=['--extern',name+'='+str(directory/filename)]
    return command


def compile(directory,target,level='2',testing=False,cfg=None):
    commands=[]
    invocation=common(directory,target,level,testing)
    for name,source in (('retained_input','retained_input.rs'),('retained_borrowed','retained_borrowed_digest.rs')):
        command=invocation+['--crate-name',name,'--crate-type','rlib',str(directory/source),
                            '-o',str(directory/('lib'+name+'.rlib'))]
        if name=='retained_borrowed':
            command+=['--extern','retained_input='+str(directory/'libretained_input.rlib')]
            if cfg: command+=['--cfg',cfg]
        subprocess.run(command,check=True,capture_output=True,timeout=90)
        commands.append(command)
    if testing:
        command=invocation+['--test',str(directory/'retained_borrowed_digest_tests.rs'),
            '--extern','retained_input='+str(directory/'libretained_input.rlib'),
            '--extern','retained_borrowed='+str(directory/'libretained_borrowed.rlib'),
            '-o',str(directory/('tests.exe' if 'windows' in target else 'tests'))]
        subprocess.run(command,check=True,capture_output=True,timeout=90)
        commands.append(command)
    return commands


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    directory=parser.parse_args().directory.resolve()
    commands,cases=prepare(directory,'x86_64-pc-windows-msvc')
    commands+=compile(directory,'x86_64-pc-windows-msvc')
    record={'native_executed':False,'strict_qualified':False,'oracle_cases':cases,'commands':commands,
            'rustc':subprocess.check_output(['rustc','+1.98.1','-vV'],text=True),
            'source_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES},
            'generated_tests_sha256':hashlib.sha256((directory/'retained_borrowed_digest_tests.rs').read_bytes()).hexdigest(),
            'archives_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.glob('*.rlib'))}}
    (directory/'retained-borrowed-build.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Retained borrowed-input Windows cross-build: PASS; native execution/strict qualification: NO')
