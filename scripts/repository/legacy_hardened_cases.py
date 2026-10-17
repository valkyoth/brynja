"""Public hardened legacy lifetime, output and behavioral mutation cases."""


def owners(family):
    return ('Authority', 'Executor', *(
        ("Stream<'static>", "in_place::Sha1Workspace<'static>", "in_place::Sha1<'static,'static>")
        if family == 'sha1' else
        ("Batch<'static>", "in_place::Workspace<'static>", "in_place::Batch<'static,'static>")))


def negatives(family):
    prefix = f'use brynja_legacy_{family}::hardened_execution as t;\n'
    workspace = 'Sha1Workspace' if family == 'sha1' else 'Workspace'
    state = 'Sha1' if family == 'sha1' else 'Batch'
    cases = [
        (f'fn escape(w:&mut t::in_place::{workspace}) {{let _=w.with(|s| s);}}', None),
        (f'fn overlap(w:&mut t::in_place::{workspace}) {{let _=w.with(|_| w.with(|_| ()) );}}', 'E0501'),
        (f'fn borrowed()->t::in_place::{workspace}<\'static> {{let e=t::Executor::portable();t::in_place::{workspace}::new(&e)}}', 'E0515'),
        (f'fn cancel(s:t::in_place::{state}) {{s.cancel();s.cancel();}}', 'E0382'),
    ]
    if family == 'sha1':
        cases += [
            ('fn public(s:t::in_place::Sha1) {let _=s.finalize_public(&mut [0;20]);}', 'E0061'),
            ('fn ordinary(a:brynja_legacy_sha1::execution::Authority) {let _=t::Executor::with_authority(a);}', 'E0308'),
            ('fn bits(s:&t::in_place::Sha1) {let _=s.check_additional_bits(u64::MAX);}', 'E0599'),
            ('fn bytes(s:&t::Stream) {let _=s.check_additional_bytes(usize::MAX);}', 'E0599'),
            ('fn copy(e:&t::Executor) {let mut out=[0;20];if let Ok(s)=e.hash_secret(b"x",&mut out){let _=s.clone();}}', 'E0599'),
        ]
    else:
        cases += [
            ('fn public(s:t::in_place::Batch) {let _=s.digest_public(&[None;8],&mut [[0;16];8],&mut brynja_legacy_md5::Md5BatchControl::new(0));}', 'E0061'),
            ('fn ordinary(a:brynja_legacy_md5::execution::Authority) {let _=t::Executor::with_authority(a,t::Mode::Require);}', 'E0308'),
        ]
    return [(prefix + text, code) for text, code in cases]


SHA1_SCOPE = r'''
use brynja_legacy_sha1::{sha1, Sha1BackendHealth, PublicDeclassification, hardened_execution::{Executor, Mode, in_place::Sha1Workspace}};
#[test]
fn scoped_abandonment_reuse_and_unwind_are_publicly_observable() -> Result<(),Box<dyn std::error::Error>> {
    for executor in [Executor::portable(),Executor::for_compiled_target(Mode::Prefer)?] {
        let mut workspace=Sha1Workspace::new(&executor);
        let bytes=[0x36;128]; let expected=sha1(&bytes)?;
        let mut out=[0xa5;20];
        for length in [0,1,19,21] {
            let mut wrong=vec![0xa5;length];
            assert!(workspace.with(|s| s.finalize_secret(&mut wrong))?.is_err());
            assert!(wrong.iter().all(|b| *b==0));assert_eq!(executor.report().health,Sha1BackendHealth::Healthy);wrong.fill(0xa5);
            assert!(workspace.with(|s| s.finalize_public(&mut wrong,PublicDeclassification::acknowledge()))?.is_err());
            assert!(wrong.iter().all(|b| *b==0xa5));assert_eq!(executor.report().health,Sha1BackendHealth::Healthy);
        }
        for mode in 0..3 {
            workspace.with(|mut s| {s.update(&bytes).unwrap();match mode {0=>s.cancel(),1=>drop(s),_=>std::mem::forget(s)}})?;
            assert_eq!(executor.report().health,Sha1BackendHealth::Healthy);
            let owned=workspace.with(|mut s| {s.update(&bytes)?;s.finalize_secret(&mut out)})??;
            assert_eq!(owned.expose(),expected);drop(owned);assert_eq!(out,[0;20]);
            assert_eq!(executor.report().health,Sha1BackendHealth::Healthy);
        }
        let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            workspace.with(|mut s| {s.update(&bytes).unwrap();std::mem::forget(s);std::panic::resume_unwind(Box::new(()))})
        }));
        assert!(result.is_err());assert_eq!(executor.report().health,Sha1BackendHealth::Quarantined);
        let mut called=false;
        assert!(workspace.with(|_| called=true).is_err());assert!(!called);
    }
    Ok(())
}
'''

MD5_SCOPE = r'''
use brynja_legacy_md5::{md5,BitString,Md5BatchControl,Md5BackendHealth,PublicDeclassification,hardened_execution::{Executor,Mode,in_place::Workspace}};
#[test]
fn scoped_abandonment_reuse_and_unwind_are_publicly_observable() -> Result<(),Box<dyn std::error::Error>> {
    for executor in [Executor::portable(),Executor::for_compiled_target(Mode::Prefer)?] {
        let mut workspace=Workspace::new(&executor);
        let bytes=[0x36;128];let inputs=[Some(BitString::new(&bytes,8).map_err(|_| "bits")?);8];
        let expected=[md5(&bytes)?;8];let mut out=[[0xa5;16];8];
        for budget in 0..24 {
            out.fill([0xa5;16]);
            assert!(workspace.with(|s| s.digest_secret(&inputs,&mut out,&mut Md5BatchControl::new(budget)))?.is_err());
            assert_eq!(out,[[0;16];8]);assert_eq!(executor.health(),Md5BackendHealth::Healthy);out.fill([0xa5;16]);
            assert!(workspace.with(|s| s.digest_public(&inputs,&mut out,&mut Md5BatchControl::new(budget),PublicDeclassification::acknowledge()))?.is_err());
            assert_eq!(out,[[0xa5;16];8]);assert_eq!(executor.health(),Md5BackendHealth::Healthy);
        }
        for mode in 0..3 {
            workspace.with(|s| match mode {0=>s.cancel(),1=>drop(s),_=>std::mem::forget(s)})?;
            assert_eq!(executor.health(),Md5BackendHealth::Healthy);
            let (owned,report)=workspace.with(|s| s.digest_secret(&inputs,&mut out,&mut Md5BatchControl::new(24)))??;
            assert_eq!(owned.expose(),expected.as_flattened());drop(owned);assert_eq!(out,[[0;16];8]);
            assert_eq!(report.work.vector_blocks,if executor.backend().is_some(){16}else{0});
            assert_eq!(executor.health(),Md5BackendHealth::Healthy);
        }
        let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            workspace.with(|s| {std::mem::forget(s);std::panic::resume_unwind(Box::new(()))})
        }));
        assert!(result.is_err());assert_eq!(executor.health(),Md5BackendHealth::Quarantined);
        let mut called=false;
        assert!(workspace.with(|_| called=true).is_err());assert!(!called);
    }
    Ok(())
}
'''


def scope(family):
    return SHA1_SCOPE if family == 'sha1' else MD5_SCOPE


def mutations(family, native):
    if family == 'sha1':
        prefix = 'hardened_execution/'
        result = [
            ('mod.rs', 'self.revoked.set(true);', 'self.revoked.set(false);'),
            ('mod.rs', 'let _ = clear_owned_region(destination);', 'let _ = destination;'),
            ('stream.rs', 'destination.copy_from_slice(&self.owner.output_staging);', 'let _ = destination;'),
            ('stream.rs', 'self.finish(tail)?;\n        output\n            .write(&self.owner.output_staging)',
             'self.finish(tail)?;\n        output\n            .write(&[0;20])'),
            ('in_place.rs', 'engine::update(owner, input, executor)', 'engine::update(owner, &[], executor)'),
            ('in_place.rs', 'destination.copy_from_slice(&self.state.owner.output_staging);', 'let _ = destination;'),
            ('in_place.rs', 'scope.completed = true;', 'scope.completed = false;'),
        ]
        if native:
            result.append(('mod.rs','Ok(authority) => Self::with_authority(authority),','Ok(_authority) => Ok(Self::portable()),'))
    else:
        prefix = 'batch/hardened_execution/'
        result = [
            ('mod.rs', 'self.owner.commit_public(output);', 'let _ = output;'),
            ('mod.rs', 'self.owner.commit_public(output);', 'self.owner.commit_public(output); if let Some(last)=output.last_mut(){last.fill(0);}'),
            ('mod.rs', 'initialization\n                .write(&lane.output_staging)', 'initialization\n                .write(&[0;16])'),
            ('in_place.rs', 'self.batch.owner.commit_public(output);', 'let _ = output;'),
            ('in_place.rs', 'initialization\n                .write(&lane.output_staging)', 'initialization\n                .write(&[0;16])'),
            ('in_place.rs', 'scope.complete = true;', 'scope.complete = false;'),
        ]
        for filename, run in (('mod.rs', 'self.run(inputs, control)?'), ('in_place.rs', 'self.batch.run(inputs, control)?')):
            initialization = ('let mut initialization = SecretRegionInitialization::begin(output.as_flattened_mut())\n'
                              '            .map_err(|_| Md5BatchError::SecretMemory)?;')
            result.append((filename, initialization + '\n        let report = ' + run + ';',
                           'let report = ' + run + ';\n        ' + initialization))
        if native:
            result.append(('mod.rs', 'vector::execute(&mut self.owner, inputs, control, a)?', 'self.owner.portable(inputs, control)?'))
            result.append(('vector.rs', 'authority\n                .compress(&mut scratch)\n                .map_err(|_| Md5BatchError::Backend)?;',
                           'let _ = &mut scratch;'))
    return [(prefix+filename,before,after) for filename,before,after in result]
