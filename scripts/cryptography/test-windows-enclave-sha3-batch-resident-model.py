#!/usr/bin/env python3
"""Focused placement-only Miri test with explicit non-crypto lifetime doubles.

Miri cannot execute the inline-assembly hardware kernel. This does NOT qualify
those kernels or replace the separate native real-component tests.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'assurance/windows-enclave-probe'


def run(directory):
    directory.mkdir()
    model='sha3_batch_accelerated_placement_model.rs'
    resident='sha3_batch_accelerated_resident.rs'
    shutil.copyfile(SOURCE/model,directory/model)
    original=(SOURCE/resident).read_text()
    # Only remove crate/test declarations: placement and destruction unchanged.
    declaration='#[cfg(test)]\nmod sha3_batch_accelerated_resident_tests;'
    if original.count(declaration)!=1 or original.count('#![no_std]')!=1:
        raise AssertionError('Stale model harness source anchor')
    original=original.replace(declaration,'').replace('#![no_std]','')
    path=directory/resident
    path.write_text(original)
    manifest=directory/'Cargo.toml'
    manifest.write_text('[package]\nname="sha3-batch-resident-memory-model"\nversion="0.0.0"\nedition="2024"\n'
                        '[workspace]\n[lib]\npath="'+model+'"\n')
    env=os.environ.copy()
    for key in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_TARGET','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER'):
        env.pop(key,None)
    env['CARGO_TARGET_DIR']=str(directory/'target')
    env['MIRIFLAGS']='-Zmiri-strict-provenance'
    tool='nightly-2026-09-11'
    command=['cargo','+'+tool,'miri','test','--offline','--manifest-path',str(manifest),'--lib']
    def execute(label,expected,diagnostic='Undefined Behavior'):
        result=subprocess.run(command,env=env,capture_output=True,text=True,timeout=120)
        (directory/(label+'.stdout')).write_text(result.stdout)
        (directory/(label+'.stderr')).write_text(result.stderr)
        if expected:
            if result.returncode or '1 passed; 0 failed' not in result.stdout:
                raise AssertionError(result.stdout+result.stderr)
        elif result.returncode==0 or diagnostic not in result.stdout+result.stderr:
            raise AssertionError('Expected memory-model rejection: '+result.stdout+result.stderr)
        return dict(stdout=result.stdout,stderr=result.stderr,exit_code=result.returncode)
    clean=execute('clean',True)
    mutations=[]
    variants=(
        ('narrowed-provenance','NonNull::from(&mut page.0).cast::<u8>()','NonNull::from(&mut page.0[0]).cast::<u8>()','Undefined Behavior'),
        ('wrong-drop-order', 'self.owner.as_ptr().drop_in_place();\n            self.authority.as_ptr().drop_in_place();',
         'self.authority.as_ptr().drop_in_place();\n            self.owner.as_ptr().drop_in_place();',
         'authority destroyed before borrowing owner'),
        ('overlap', 'backing.as_ptr().add(OWNER_OFFSET)', 'backing.as_ptr().add(0)', 'Undefined Behavior'),
    )
    for label,before,after,diagnostic in variants:
        if original.count(before)!=1:raise AssertionError('Stale placement model mutation: '+label)
        try:
            path.write_text(original.replace(before,after))
            mutations.append(dict(name=label,before=before,after=after,diagnostic=diagnostic,result=execute(label,False,diagnostic)))
        finally:path.write_text(original)
    final=execute('restored',True)
    paths=[SOURCE/model,SOURCE/resident,Path(__file__).resolve()]
    record=dict(schema=1,status='PLACEMENT_MODEL_PASS',cryptographic_execution=False,enclave_execution=False,
                production_qualified=False,toolchain=tool,miriflags=env['MIRIFLAGS'],command=command,
                source_sha256={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
                clean=clean,mutations=mutations,final=final)
    (directory/'placement-model-results.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Placement-only Miri model passes; three unsafe memory regressions rejected; no crypto/enclave qualification')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    args=parser.parse_args()
    run(args.directory.resolve())
