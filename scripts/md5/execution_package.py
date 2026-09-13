"""Compiled ordinary MD5 ownership, output mutations and independent oracle."""
import importlib.util
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def run(consumer, env, args, passed=True):
    result = subprocess.run(['cargo', *args],cwd=consumer,env=env,text=True,capture_output=True,timeout=180)
    if (result.returncode == 0) != passed:
        raise ValueError('unexpected packaged MD5 command result:\n'+result.stdout[-2000:]+result.stderr[-4000:])
    return result


def prepare(consumer, root):
    (consumer/'src/main.rs').write_bytes((ROOT/'assurance/md5-execution/src/main.rs').read_bytes())
    (consumer/'tests').mkdir()
    for package, name in (('brynja-legacy-md5','execution'),('brynja-legacy-md5-std','hosted')):
        (consumer/f'tests/{name}.rs').write_bytes((ROOT/f'crates/{package}/tests/execution.rs').read_bytes())
        (consumer/f'{name}.md').write_bytes((root/f'unpacked/{package}-0.1.0/README.md').read_bytes())
    library=consumer/'src/lib.rs'
    library.write_text(library.read_text()+'\n#[doc = include_str!("../execution.md")]\npub struct LeafReadme;\n#[doc = include_str!("../hosted.md")]\npub struct HostedReadme;\n')


def check(consumer, root, env):
    library=consumer/'src/lib.rs'
    original=library.read_bytes()
    count=0
    for identity in ('Authority','Executor'):
        for trait in ('Send','Sync','Copy','Clone','core::fmt::Debug'):
            library.write_text(f'use brynja_legacy_md5::execution::{identity};\nfn bound<T:{trait}>(){{}}\npub fn probe(){{bound::<{identity}>();}}\n')
            result=run(consumer,env,['check','--locked','--offline','--lib'],False)
            if 'E0277' not in result.stderr: raise ValueError('ownership negative failed for unrelated reason')
            count+=1
    for method in ('session','compress'):
        library.write_text(f'pub fn probe(a:brynja_legacy_md5::execution::Authority){{a.{method}();}}\n')
        result=run(consumer,env,['check','--locked','--offline','--lib'],False)
        if not any(code in result.stderr for code in ('E0624','E0599')): raise ValueError('raw-session negative failed unexpectedly')
        count+=1
    library.write_text('pub fn probe(e:brynja_legacy_md5::execution::Executor){let _=e.digest(&[None;8],&mut [[0;16];8],&mut brynja_legacy_md5::Md5BatchControl::new(0));}\n')
    if 'E0061' not in run(consumer,env,['check','--locked','--offline','--lib'],False).stderr:
        raise ValueError('public-data classification was not required')
    library.write_bytes(original)
    run(consumer,env,['build','--locked','--offline','--release'])
    binary=Path(env['CARGO_TARGET_DIR'])/'release/md5-packaged-consumer'
    if not binary.is_file(): binary=binary.with_suffix('.exe')
    spec=importlib.util.spec_from_file_location('operational_oracle',ROOT/'scripts/md5/check-md5-execution-differential.py')
    oracle=importlib.util.module_from_spec(spec); spec.loader.exec_module(oracle)
    # Read the real report for an eligible batch; then require the oracle's exact
    # counters for that width. Native callers additionally enforce the ISA lane.
    probe=('512:'+'00'*64+' ')*8+'\n'
    result=subprocess.run([binary,'prefer'],input=probe,text=True,capture_output=True,check=True,timeout=30)
    width=int(result.stdout.split()[-3])
    if width not in (0,4,8): raise ValueError('invalid reported width')
    if env.get('BRYNJA_REQUIRE_MD5_EXECUTION') and not width: raise ValueError('packaged execution silently portable')
    oracle.campaign(binary,'portable',0)
    oracle.campaign(binary,'prefer',width)
    oracle.campaign(binary,'hosted',width)
    if width: oracle.campaign(binary,'require',width)
    path=root/'unpacked/brynja-legacy-md5-0.1.0/src/batch/execution.rs'
    source=path.read_text()
    mutations=(
        ('owner.commit_public(output);','let _ = output;'),
        ('owner.commit_public(output);','owner.commit_public(output); if let Some(last) = output.last_mut() { last.fill(0); }'),
        ('let work = match result','let mut work = match result'),
        ('let work = match result','let mut work = match result'),
        ('let backend = authority','let backend = None::<&Authority>'),
        ('vector::execute(&mut owner, inputs, control, a.session())','owner.portable(inputs, control)'),
    )
    for index,(old,new) in enumerate(mutations):
        if source.count(old)!=1: raise ValueError('mutation site ambiguous')
        changed=source.replace(old,new,1)
        if index in (2,3):
            field='scalar_blocks' if index==2 else 'vector_blocks'
            changed=changed.replace('owner.commit_public(output);',f'work.{field} += 1; owner.commit_public(output);')
        if index in (4,5) and not width: continue
        try:
            path.write_text(changed)
            # Require a real assertion failure, not a broken mutation build.
            run(consumer,env,['test','--locked','--offline','--test','execution','--no-run'])
            result=run(consumer,env,['test','--locked','--offline','--test','execution'],False)
            if 'test result: FAILED' not in result.stdout: raise ValueError('mutant did not fail a runtime assertion')
        finally: path.write_text(source)
    run(consumer,env,['test','--locked','--offline','--test','execution'])
    print(f'Packaged MD5 operational: {count+1} ownership/classification negatives; {6 if width else 4} compiled output/report mutants rejected')
