#!/usr/bin/env python3
"""Build isolated secret-to-secret composition, never native qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import windows_enclave_retained_build as base
import windows_enclave_hardened_build as hardened
from windows_enclave_retained_native_host_build import replace

ROOT,SOURCE=base.ROOT,base.SOURCE
FILES=('persistent_transform.rs','persistent_transform_tests.rs','retained_rehash.rs',
       'retained_placement_rehash.rs','retained_rehash_tests.rs','retained_placement.rs')
SOURCES=tuple(sorted(set(base.SOURCES)|{'assurance/windows-enclave-probe/'+n for n in FILES}|{
    'scripts/cryptography/windows_enclave_retained_rehash_build.py',
    'scripts/cryptography/test-windows-enclave-retained-rehash.py',
    'scripts/cryptography/windows_enclave_hardened_build.py',
    'scripts/cryptography/windows_enclave_retained_native_host_build.py'}))
VARIANTS={'normal':None,'scratch':'probe_transform_skip_scratch_clear',
          'token':'probe_transform_ignore_token','failure':'probe_transform_ignore_failure',
          'commit':'probe_transform_skip_commit','generation':'probe_transform_reuse_generation'}


def prepare(directory,target,testing=False):
    hardened.layout_check()
    commands=base.build(directory,target,panic='unwind' if testing else 'abort')
    for name in FILES:shutil.copyfile(SOURCE/name,directory/name)
    for name,fragment in [('persistent_result','persistent_transform'),('retained_digest','retained_rehash'),
                          ('retained_placement','retained_placement_rehash')]:
        source=(SOURCE/(name+'.rs')).read_text()
        anchor='#[cfg(test)]\n#[path = "'+name+'_tests.rs"]\nmod tests;'
        source=replace(source,anchor,'include!("'+fragment+'.rs");'+(
            '\n#[cfg(test)]\n#[path = "persistent_transform_tests.rs"]\nmod tests;' if name=='persistent_result' else ''))
        (directory/(name+'.rs')).write_text(source)
    vectors=base.base.base.vectors()+[bytes((i*29+n)%256 for i in range(n)) for n in range(130)]
    rows=['#[test]','fn independent_rehash_chains_preserve_secret_ownership() {']
    for message in vectors:
        value=hashlib.sha256(message).digest();chain=[]
        for _ in range(4):
            value=hashlib.sha256(value).digest();chain.append('['+','.join(map(str,value))+']')
        rows.append('oracle(&['+','.join(map(str,message))+'], &['+','.join(chain)+']);')
    tests=directory/'retained_rehash_tests.rs'
    tests.write_text(tests.read_text()+'\n'+'\n'.join(rows+['}','']))
    return commands,len(vectors)


def common(directory,target,level,testing):
    return ['rustc','+1.98.1','--edition=2024','--target',target,'-D','warnings',
            '-C','opt-level='+level,'-C','overflow-checks=yes','-C','panic='+('unwind' if testing else 'abort'),
            '-L','dependency='+str(directory),'--extern','brynja_core='+str(directory/'libbrynja_core.rlib'),
            '--extern','brynja_hash_sha2='+str(directory/'libbrynja_hash_sha2.rlib')]


def compile(directory,target,level='2',testing=False,variant='normal'):
    commands=[];args=common(directory,target,level,testing);deps=[];cfg=VARIANTS[variant]
    for name in ('persistent_result','retained_digest','retained_placement'):
        command=args+deps+['--crate-name',name,'--crate-type','rlib',str(directory/(name+'.rs')),
                           '-o',str(directory/('lib'+name+'_rehash.rlib'))]
        if cfg and name=='persistent_result':command+=['--cfg',cfg]
        subprocess.run(command,check=True,capture_output=True,timeout=90);commands.append(command)
        deps+=['--extern',name+'='+str(directory/('lib'+name+'_rehash.rlib'))]
    if testing:
        for name,source,extra in [('slot','persistent_result.rs',[]),('rehash','retained_rehash_tests.rs',deps)]:
            command=args+extra+['--test',str(directory/source),'-o',str(directory/(name+'-test'))]
            if name=='slot' and cfg:command+=['--cfg',cfg]
            subprocess.run(command,check=True,capture_output=True,timeout=90);commands.append(command)
    return commands


def miri(directory):
    """Bounded component memory-model checks, not OS execution evidence."""
    for name in ('persistent_result','retained_digest','retained_placement'):
        package=directory/('miri-'+name);package.mkdir()
        lines=['[package]',f'name = "{name}"','version = "0.0.0"','edition = "2024"','[workspace]',
               '[lib]','path = '+json.dumps(str(directory/(name+'.rs'))),'[dependencies]']
        for dep in ('brynja-core','brynja-hash-sha2'):
            lines.append(dep+' = { path = '+json.dumps(str(ROOT/'crates'/dep))+', default-features = false }')
        for dep in ('persistent_result','retained_digest'):
            if dep==name:break
            lines.append(dep+' = { path = '+json.dumps(str(directory/('miri-'+dep)))+' }')
        if name=='persistent_result':
            cfgs=[v for v in list(base.VARIANTS.values())+list(VARIANTS.values()) if v]
            lines+=['[lints.rust]','unexpected_cfgs = { level = "deny", check-cfg = ['+
                    ', '.join(json.dumps('cfg('+v+')') for v in cfgs)+'] }']
        if name=='retained_placement':
            lines+=['[[test]]','name = "composition"','path = '+json.dumps(str(directory/'retained_rehash_tests.rs'))]
        (package/'Cargo.toml').write_text('\n'.join(lines)+'\n')
    tool='nightly-2026-09-11';commands=[]
    for package,filters in [('persistent_result',[['--lib']]),('retained_placement',[
        ['--test','composition','distinct_owner_and_stale_generation'],
        ['--test','composition','cancelled_or_dropped_composed_result']])]:
        manifest=directory/('miri-'+package)/'Cargo.toml'
        commands.append(['cargo','+'+tool,'generate-lockfile','--offline','--manifest-path',str(manifest)])
        for filters_for_run in filters:
            commands.append(['cargo','+'+tool,'miri','test','--locked','--offline','--manifest-path',str(manifest)]+filters_for_run)
    env=os.environ.copy()
    for key in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTDOCFLAGS','CARGO_BUILD_TARGET','MIRIFLAGS'):env.pop(key,None)
    env['MIRIFLAGS']='-Zmiri-strict-provenance';env['CARGO_TARGET_DIR']=str(directory/'miri-build')
    for index,command in enumerate(commands):
        print('RUN:', ' '.join(command),flush=True)
        result=subprocess.run(command,env=env,capture_output=True,text=True,timeout=180)
        (directory/f'miri-{index}.stdout').write_text(result.stdout);(directory/f'miri-{index}.stderr').write_text(result.stderr)
        print(result.stdout,end='');print(result.stderr,end='');result.check_returncode()
        if 'miri' in command:
            expected='4 passed' if '--lib' in command else '1 passed'
            if expected not in result.stdout:raise ValueError('Miri filter did not execute the required tests')
    return commands


def build(directory,with_miri=False):
    target='x86_64-pc-windows-msvc';directory=directory.resolve()
    commands,cases=prepare(directory,target);commands+=compile(directory,target)
    if with_miri:commands+=miri(directory)
    record={'native_executed':False,'strict_qualified':False,'target':target,'oracle_inputs':cases,
            'oracle_outputs':cases*4,'commands':commands,'miri':with_miri,
            'miriflags':'-Zmiri-strict-provenance' if with_miri else None,
            'miri_rustc':subprocess.check_output(['rustc','+nightly-2026-09-11','-vV'],text=True) if with_miri else None,
            'miri_version':subprocess.check_output(['cargo','+nightly-2026-09-11','miri','--version'],text=True) if with_miri else None,
            'rustc':subprocess.check_output(['rustc','+1.98.1','-vV'],text=True),
            'source_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES},
            'generated_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.glob('*.rs'))},
            'archives_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.glob('*.rlib'))}}
    (directory/'retained-rehash-build.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Retained secret composition cross-build: PASS; native execution/strict qualification: NO')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path)
    parser.add_argument('--miri',action='store_true');args=parser.parse_args()
    build(args.directory,args.miri)
