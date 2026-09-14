"""External-package API separation, independent bit oracle and real mutants."""
import importlib.util
import subprocess
from pathlib import Path
from execution_package import run, ROOT


def prepare(consumer, root):
    (consumer/'src/main.rs').write_bytes((ROOT/'assurance/md5-hardened-execution/src/main.rs').read_bytes())
    (consumer/'tests').mkdir()
    for package, name in (('brynja-legacy-md5','hardened_execution'),('brynja-legacy-md5-std','hosted')):
        source = ROOT/f'crates/{package}/tests/hardened_execution.rs'
        (consumer/f'tests/{name}.rs').write_bytes(source.read_bytes())
        (consumer/f'{name}.md').write_bytes((root/f'unpacked/{package}-0.1.0/README.md').read_bytes())
    library=consumer/'src/lib.rs'
    library.write_text(library.read_text()+'\n#[doc = include_str!("../hardened_execution.md")]\npub struct LeafReadme;\n#[doc = include_str!("../hosted.md")]\npub struct HostedReadme;\n')


def check(consumer, root, env):
    library = consumer/'src/lib.rs'
    original = library.read_bytes()
    count = 0
    for identity in ('Authority','Executor',"Batch<'static>"):
        for trait in ('Send','Sync','Copy','Clone','core::fmt::Debug'):
            library.write_text(f'use brynja_legacy_md5::hardened_execution::*;\nfn bound<T:{trait}>(){{}}\npub fn probe(){{bound::<{identity}>();}}\n')
            require_error(run(consumer,env,['check','--locked','--offline','--lib'],False), ('E0277',))
            count += 1
    probes = (
        ('pub fn probe(a:brynja_legacy_md5::execution::Authority){let _=brynja_legacy_md5::hardened_execution::Executor::with_authority(a,brynja_legacy_md5::hardened_execution::Mode::Require);}', ('E0308',)),
        ('pub fn probe(b:brynja_legacy_md5::hardened_execution::Batch){let _=b.digest_public(&[None;8],&mut [[0;16];8],&mut brynja_legacy_md5::Md5BatchControl::new(0));}', ('E0061',)),
        ('pub fn probe(b:brynja_legacy_md5::hardened_execution::Batch){let mut o=[[0;16];8];let _=b.digest_secret(&[None;8],&mut o,&mut brynja_legacy_md5::Md5BatchControl::new(0));let _=b.digest_secret(&[None;8],&mut o,&mut brynja_legacy_md5::Md5BatchControl::new(0));}', ('E0382',)),
        ('pub fn probe(a:brynja_legacy_md5::hardened_execution::Authority){let _=a.compress();}', ('E0624',)),
    )
    for source, codes in probes:
        library.write_text(source)
        require_error(run(consumer,env,['check','--locked','--offline','--lib'],False), codes)
        count += 1
    library.write_bytes(original)
    run(consumer,env,['build','--locked','--offline','--release'])
    binary=Path(env['CARGO_TARGET_DIR'])/'release/md5-packaged-consumer'
    if not binary.is_file(): binary=binary.with_suffix('.exe')
    probe=('512:'+'00'*64+' ')*8+'\n'
    result=subprocess.run([binary,'prefer'],input=probe,text=True,capture_output=True,check=True,timeout=30)
    width=int(result.stdout.split()[-3])
    if width not in (0,4,8) or (env.get('BRYNJA_REQUIRE_HARDENED_MD5') and not width):
        raise ValueError('required hardened SIMD missing')
    spec=importlib.util.spec_from_file_location('hardened_oracle',ROOT/'scripts/md5/check-md5-execution-differential.py')
    oracle=importlib.util.module_from_spec(spec); spec.loader.exec_module(oracle)
    for mode, expected in (('portable',0),('prefer',width),('hosted',width)):
        oracle.campaign(binary,mode,expected)
    if width: oracle.campaign(binary,'require',width)
    path=root/'unpacked/brynja-legacy-md5-0.1.0/src/batch/hardened_execution/mod.rs'
    source=path.read_text()
    mutations=[('self.owner.commit_public(output);','let _ = output;'),
               ('self.owner.commit_public(output);','self.owner.commit_public(output); if let Some(last)=output.last_mut(){last.fill(0);}'),
               ('self.executor.ready()?;','let _ = self.executor;')]
    if width: mutations.append(('vector::execute(&mut self.owner, inputs, control, a)?','self.owner.portable(inputs, control)?'))
    for old,new in mutations:
        if old not in source: raise ValueError('missing compiled mutation site')
        try:
            path.write_text(source.replace(old,new))
            run(consumer,env,['test','--locked','--offline','--test','hardened_execution','--no-run'])
            result=run(consumer,env,['test','--locked','--offline','--test','hardened_execution'],False)
            if 'test result: FAILED' not in result.stdout: raise ValueError('mutant was not a test assertion failure')
        finally: path.write_text(source)
    run(consumer,env,['test','--locked','--offline','--test','hardened_execution'])
    cleanup_mutants(consumer,root,env)
    print(f'Packaged hardened MD5: {count} ownership/classification negatives; {len(mutations)} compiled algorithm/health mutants rejected')


def cleanup_mutants(consumer,root,env):
    import md5_hardened_codegen as codegen
    identity=subprocess.check_output(['rustc','+1.98.1','-vV'],env=env,text=True)
    targets=[line.removeprefix('host: ') for line in identity.splitlines() if line.startswith('host: ')]
    if len(targets)!=1 or targets[0] not in ('x86_64-unknown-linux-gnu','aarch64-unknown-linux-gnu','aarch64-apple-darwin'):
        raise ValueError('unsupported cleanup evidence host')
    target=targets[0]
    path=root/'unpacked/brynja-legacy-md5-0.1.0/src/cpu/scratch.rs'
    source=path.read_text()
    codegen.compile_and_check(root/'cleanup','1.98.1',target,manifest=consumer/'Cargo.toml')
    changes=[(f'let _ = clear_owned_region(self.{field}.as_flattened_mut());',f'let _ = &mut self.{field};')
             for field in ('initial','words','work','temporary')]
    changes.append(('self.wipe();','let _ = self;'))
    for old,new in changes:
        if source.count(old)!=1: raise ValueError('cleanup mutant site ambiguous')
        try:
            path.write_text(source.replace(old,new))
            # A compilation failure is NOT successful mutation rejection.
            try: codegen.compile_and_check(root/'cleanup','1.98.1',target,manifest=consumer/'Cargo.toml')
            except (ValueError, codegen.flow.MirCleanupFlowError): pass
            else: raise AssertionError('compiled cleanup mutant escaped')
        finally: path.write_text(source)
    codegen.compile_and_check(root/'cleanup','1.98.1',target,manifest=consumer/'Cargo.toml')
    print('Packaged hardened MD5 cleanup: 5 compiled whole-region/Drop mutants rejected')


def require_error(result, codes):
    if not any(code in result.stderr for code in codes):
        raise ValueError('negative failed for an unrelated compiler error:\n'+result.stderr)
