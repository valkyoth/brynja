#!/usr/bin/env python3
"""Miri placement/rollback model; deliberately does not execute SIMD kernels."""
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
    directory.mkdir(parents=True,exist_ok=False)
    model='sha256_simd_placement_model.rs'
    resident='sha256_simd_resident.rs'
    shutil.copyfile(SOURCE/model,directory/model)
    original=(SOURCE/resident).read_text()
    declaration='#[cfg(test)]\nmod sha256_simd_resident_tests;'
    assert original.count(declaration)==1 and original.count('#![no_std]')==1
    original=original.replace(declaration,'').replace('#![no_std]','')
    path=directory/resident
    path.write_text(original)
    manifest=directory/'Cargo.toml'
    manifest.write_text('[package]\nname="sha256-simd-placement-model"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[lib]\npath="'+model+'"\n')
    env=os.environ.copy()
    for key in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_TARGET','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER'):
        env.pop(key,None)
    env['CARGO_TARGET_DIR']=str(directory/'target')
    env['MIRIFLAGS']='-Zmiri-strict-provenance'
    tool='nightly-2026-09-11'
    command=['cargo','+'+tool,'miri','test','--offline','--manifest-path',str(manifest),'--lib']
    sources={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (SOURCE/model,SOURCE/resident,Path(__file__).resolve())}
    def execute(label,expected,diagnostic='Undefined Behavior'):
        result=subprocess.run(command,env=env,capture_output=True,text=True,timeout=120)
        (directory/(label+'.stdout')).write_text(result.stdout)
        (directory/(label+'.stderr')).write_text(result.stderr)
        if expected:
            if result.returncode or '1 passed; 0 failed' not in result.stdout:
                raise AssertionError(result.stdout+result.stderr)
        elif result.returncode==0 or diagnostic not in result.stdout+result.stderr:
            raise AssertionError('Model mutant was not rejected: '+result.stdout+result.stderr)
        return dict(stdout=result.stdout,stderr=result.stderr,exit_code=result.returncode)
    clean=execute('clean',True)
    mutations=[]
    for label,before,after,diagnostic in (
        ('narrowed-provenance','NonNull::from(&mut page.0).cast::<u8>()','NonNull::from(&mut page.0[0]).cast::<u8>()','Undefined Behavior'),
        ('wrong-drop-order','self.owner.as_ptr().drop_in_place();\n            self.authority.as_ptr().drop_in_place();',
         'self.authority.as_ptr().drop_in_place();\n            self.owner.as_ptr().drop_in_place();','authority destroyed before borrowing owner'),
        ('overlap','backing.as_ptr().add(OWNER_OFFSET)','backing.as_ptr().add(0)','Undefined Behavior'),
        ('authority-failure-clear','clear_page(backing);\n                    return Err(Error::Backend);','return Err(Error::Backend);','assertion `left == right` failed'),
        ('owner-failure-clear','clear_page(backing);\n                    return Err(error);','return Err(error);','assertion `left == right` failed'),
        ('owner-failure-authority-drop','authority.as_ptr().drop_in_place();\n                    clear_page(backing);','clear_page(backing);','assertion `left == right` failed'),
    ):
        assert original.count(before)==1,label
        print('PLACEMENT_MODEL_MUTATION: '+label,flush=True)
        try:
            path.write_text(original.replace(before,after))
            mutations.append(dict(name=label,before=before,after=after,result=execute(label,False,diagnostic)))
        finally:path.write_text(original)
    final=execute('restored',True)
    assert all(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==expected for name,expected in sources.items())
    record=dict(schema=1,status='PLACEMENT_MODEL_PASS',cryptographic_execution=False,enclave_execution=False,
        production_qualified=False,toolchain=tool,miriflags=env['MIRIFLAGS'],command=command,
        source_sha256=sources,clean=clean,mutations=mutations,final=final)
    (directory/'placement-model-results.json').write_text(json.dumps(record,indent=2)+'\n')
    print('SHA256 SIMD placement-only Miri: six memory/rollback regressions rejected; not crypto/enclave qualification')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    run(parser.parse_args().directory.resolve())
