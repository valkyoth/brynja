#!/usr/bin/env python3
"""Packaged static x86 startup review on a probed native AES/SSE2 host."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import tempfile

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('x86_startup_linked',HERE/'check-aes-accelerated-linked.py')
linked=importlib.util.module_from_spec(spec);spec.loader.exec_module(linked)
packaged,campaigns=linked.packaged,linked.campaigns
ROOT,require=linked.ROOT,linked.require
TARGET='x86_64-unknown-linux-gnu'


def probe_host(root,env,compiler):
    require(compiler in ('1.90.0','1.99.1'),'unsupported x86 startup compiler')
    probe=root/'probe'
    packaged.archives.run(['rustc','+'+compiler,'--edition=2024',
        str(ROOT/'assurance/aes-kernel-candidate/probe.rs'),'--target',TARGET,'-o',str(probe)],root,env)
    observed=packaged.archives.run([str(probe)],root,env)
    require(not observed.stderr and observed.stdout.splitlines()==['AES_STATIC_HOST_BUNDLE_PASS'],'ISA probe failed')
    return observed.stdout


def check(compiler,capture_only=False):
    require(compiler in ('1.90.0','1.99.1'),'unsupported x86 startup compiler')
    require(platform.system()=='Linux' and platform.machine()=='x86_64','requires Linux x86 host')
    for name in (*packaged.archives.REJECT_ENV,'PYTHONOPTIMIZE','PYTHONPATH'):
        require(name not in os.environ,'remove ambient '+name)
    source=ROOT/'assurance/aes-accelerated-campaigns/startup-x86.rs'
    require(source.is_file() and not any(p.is_symlink() for p in (source,*source.parents)),
            'missing or symlinked startup fixture')
    tools=[]
    for name in ('llvm-nm','llvm-objdump'):
        path=shutil.which(name);require(path is not None,'missing '+name)
        tools.append(Path(path).resolve(strict=True))
    hashes=[linked.digest(p) for p in tools]
    base=ROOT/'target/aes-accelerated-startup-x86';base.mkdir(parents=True,exist_ok=True)
    retained=Path(tempfile.mkdtemp(prefix=compiler+'-',dir=base))
    print(f'Artifacts: {retained}',flush=True)
    with packaged.archives.cargo_environment.private_directory(ROOT) as temporary:
        root=Path(temporary);env=packaged.archives.isolated_env(root)
        # This binary has no globally enabled AES feature. Refuse execution of
        # target-feature-enabled consumers unless the actual host is suitable.
        (retained/'host-probe.log').write_text(probe_host(root,env,compiler))
        versions=packaged.package_sources(root,env);cargo=['cargo','+'+compiler]
        for route in ('direct','facade'):
            directory=root/'consumers'/route;(directory/'src').mkdir(parents=True)
            shutil.copyfile(source,directory/'src/main.rs')
            (directory/'Cargo.toml').write_text(campaigns.manifest(versions,route,'static')+
                'opt-level=3\nlto="fat"\ncodegen-units=1\nstrip=false\n')
            packaged.archives.run(cargo+['generate-lockfile','--offline'],directory,env)
            selection=['--locked','--offline','--no-default-features','--features',route]
            metadata=packaged.archives.run(cargo+['metadata','--format-version=1',*selection,'--filter-platform',TARGET],directory,env)
            campaigns.graph(json.loads(metadata.stdout),versions,directory,route,'static')
            (retained/f'{route}-metadata.json').write_text(metadata.stdout)
            for panic in ('abort','unwind'):
                label=route+'-'+panic
                build_env=dict(env,RUSTFLAGS='-Ctarget-feature=+aes,+sse2',
                    CARGO_PROFILE_RELEASE_PANIC=panic,CARGO_TARGET_DIR=str(root/label))
                print(f'Building x86 startup {compiler} {label}',flush=True)
                build=packaged.archives.run(cargo+['build',*selection,'--release','--target',TARGET],directory,build_env)
                (retained/f'{label}-build.log').write_text(build.stdout+build.stderr)
                binary=retained/f'{label}.elf';shutil.copyfile(root/label/TARGET/'release'/campaigns.NAME,binary)
                binary.chmod(0o700);digest=linked.digest(binary)
                nm=packaged.archives.run([str(tools[0]),'--print-size','--defined-only',str(binary)],directory,env)
                asm=packaged.archives.run([str(tools[1]),'--disassemble','--no-print-imm-hex',str(binary)],directory,env)
                require(not nm.stderr and not asm.stderr,'startup inspection diagnostic')
                (retained/f'{label}.nm').write_text(nm.stdout);(retained/f'{label}.asm').write_text(asm.stdout)
                execution=packaged.archives.run([str(binary)],directory,env)
                require(not execution.stderr and execution.stdout.splitlines()==['AES_X86_STARTUP_PASS'],
                        'startup execution population changed')
                (retained/f'{label}-execution.log').write_text(execution.stdout)
                report=dict(compiler=compiler,route=route,panic=panic,target=TARGET,admission='static',
                    profile=linked.PROFILE,execution='local-native',binary_sha256=digest,
                    tools=[dict(path=str(p),sha256=h) for p,h in zip(tools,hashes)])
                if not capture_only:
                    reviewer=packaged.module('x86_startup_review',HERE/'aes_accelerated_startup_x86.py')
                    report['review']=reviewer.inspect(nm.stdout,asm.stdout,binary.read_bytes(),compiler,panic)
                    negative=root/(label+'-corrupt.elf');rejected=[]
                    for case,changed in reviewer.corruption_cases(binary.read_bytes(),report['review']['references']):
                        negative.write_bytes(changed);negative.chmod(0o700)
                        result=packaged.archives.run([str(negative),'expect-quarantined'],directory,env)
                        require(not result.stderr and result.stdout.splitlines()==['AES_X86_STARTUP_QUARANTINED'],
                                'corrupted startup answer was not quarantined: '+case)
                        rejected.append(case)
                    require(len(rejected)==628 and len(set(rejected))==628,'startup quarantine population changed')
                    report['executed_quarantine_cases']=rejected
                    print(f'{label}: 628 corrupted-answer executions quarantined',flush=True)
                require(linked.digest(binary)==digest and [linked.digest(p) for p in tools]==hashes,
                        'startup binary or inspection tool changed')
                (retained/f'{label}.json').write_text(json.dumps(report,indent=2)+'\n')
    if capture_only:
        print('AES x86 startup CAPTURE ONLY: four native consumers; machine review NOT performed')
    else:
        print(f'AES_X86_STARTUP_LINKED_PASS: {compiler}; four static native consumers')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain',choices=('1.90.0','1.99.1'),required=True)
    parser.add_argument('--capture-only',action='store_true')
    args=parser.parse_args()
    try:check(args.toolchain,args.capture_only)
    except (OSError,ValueError) as error:raise SystemExit('AES x86 startup failed: '+str(error))
