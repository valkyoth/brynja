"""External Linux legacy protected-session tests; synthetic public inputs only."""

COMMON = r'''
#![forbid(unsafe_code)]
use brynja_legacy_FAMILY_std::strict_execution as api;
type Result<T> = std::result::Result<T,Box<dyn std::error::Error>>;
fn limits() -> api::Limits { api::Limits { stack_bytes:262144,
    max_stack_mapping_bytes:1048576,max_output_mapping_bytes:65536,
    max_message_bits:65536,max_chunks:8 } }
fn hex(s:&str)->Vec<u8> {
    if s=="-" {return vec![];}
    s.as_bytes().chunks(2).map(|c|u8::from_str_radix(std::str::from_utf8(c).unwrap(),16).unwrap()).collect()
}
fn rows()->Vec<(usize,Vec<u8>,Vec<u8>)> {
    include_str!("legacy.txt").lines().map(|line| {
        let c:Vec<_>=line.split_whitespace().collect();
        (c[0].parse().unwrap(),hex(c[1]),hex(c[COLUMN]))
    }).collect()
}
macro_rules! corpus {
    ($session:expr) => {{
        let mut session=$session;
        let cases=rows();assert_eq!(cases.len(),169);
        for (bits,input,expected) in &cases {
            let valid=if *bits==0{0}else{((bits-1)%8+1) as u8};
            let split=input.len().saturating_sub(1).min(17);
            let (head,tail)=input.split_at(split);
            let output=session.hash_chunks(&[&[],head,&[]],tail,valid,&api::Cancellation::new())?;
            assert_eq!(output.expose(),expected);drop(output);
            let output=session.hash_chunks(&[head],tail,valid,&api::Cancellation::new())?;
            let mut public=[0xa5;WIDTH];
            output.declassify(&mut public,api::PublicDeclassification::acknowledge())?;
            assert_eq!(public.as_slice(),expected);
            if bits%8==0 {assert_eq!(session.hash(input)?.expose(),expected);}
        }
    }};
}
macro_rules! lifecycle {
    ($session:expr) => {{
        let mut session=$session;
        let expected=hex(ABC);
        let cancel=api::Cancellation::new();cancel.cancel();
        assert!(matches!(session.hash_chunks(&[b"abc"],&[],0,&cancel),Err(api::Error::Cancelled)));
        assert!(matches!(session.hash_chunks(&[&[][..];9],&[],0,&api::Cancellation::new()),Err(api::Error::WorkLimit)));
        assert!(matches!(session.hash(&[0;8193]),Err(api::Error::WorkLimit)));
        for (tail,valid) in [(&[][..],1),(&[0][..],0),(&[0][..],9),(&[1][..],1)] {
            assert!(matches!(session.hash_chunks(&[],tail,valid,&api::Cancellation::new()),Err(api::Error::InvalidBits)));
            assert_eq!(session.hash(b"abc")?.expose(),expected);
        }
        for size in [0,WIDTH-1,WIDTH+1] {
            let mut public=vec![0xa5;size];
            assert_eq!(session.hash(b"abc")?.declassify(&mut public,api::PublicDeclassification::acknowledge()),Err(api::Error::OutputLength));
            assert!(public.iter().all(|b|*b==0xa5));
        }
        std::mem::forget(session.hash(b"different input")?);
        assert_eq!(session.hash(b"abc")?.expose(),expected);
        let unwind=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let output=session.hash(b"different input").unwrap();
            std::mem::forget(output);std::panic::resume_unwind(Box::new(()));
        }));
        assert!(unwind.is_err());
        // Caller unwind occurs after a completed worker. It is not a worker fault.
        assert_eq!(session.hash(b"abc")?.expose(),expected);
    }};
}
#[test] fn scalar_corpus()->Result<()> { corpus!(api::Session::new(limits())?);Ok(()) }
#[test] fn scalar_lifecycle()->Result<()> { lifecycle!(api::Session::new(limits())?);Ok(()) }
#[test] fn invalid_resources_reject()->Result<()> {
    let mut invalid=limits();invalid.max_chunks=0;
    assert!(matches!(api::Session::new(invalid),Err(api::Error::InvalidLimits)));
    let mut invalid=limits();invalid.max_output_mapping_bytes=0;
    assert!(api::Session::new(invalid).is_err());
    let mut invalid=limits();invalid.max_stack_mapping_bytes=0;
    assert!(api::Session::new(invalid).is_err());
    Ok(())
}
'''

SHA1 = r'''
#[test] fn compiled_admission_and_corpus()->Result<()> {
    if !cfg!(any(all(target_arch="x86_64",target_feature="sha",target_feature="sse2"),
                 all(target_arch="aarch64",target_feature="neon",target_feature="sha2"))) {
        assert!(!cfg!(feature="native"));
        assert!(matches!(api::CompiledSession::new(limits()),Err(api::Error::Execution(
            brynja_legacy_sha1::hardened_execution::Error::Backend(brynja_legacy_sha1::Sha1BackendError::MissingFeatures)))));
        return Ok(());
    }
    {
        let session=api::CompiledSession::new(limits())?;
        #[cfg(target_arch="x86_64")] assert_eq!(session.backend(),brynja_legacy_sha1::Sha1Backend::X86Sha);
        #[cfg(target_arch="aarch64")] assert_eq!(session.backend(),brynja_legacy_sha1::Sha1Backend::Aarch64Sha1);
        corpus!(session);lifecycle!(api::CompiledSession::new(limits())?);
        let mut session=api::CompiledSession::new(limits())?;
        std::mem::forget(session.hash(b"abc")?);session.quarantine();
        assert!(session.is_quarantined());
        assert!(matches!(session.hash(b"abc"),Err(api::Error::Quarantined)));
        println!("\nSTRICT_LEGACY_NATIVE: sha1; corpus=169");
    }
    Ok(())
}
'''

MD5 = r'''
fn batch_limits()->api::batch::Limits {api::batch::Limits {stack_bytes:262144,
    max_stack_mapping_bytes:1048576,max_output_mapping_bytes:65536,max_input_bits:524288}}
#[test] fn compiled_admission_and_corpus()->Result<()> {
    if !cfg!(any(all(target_arch="x86_64",target_feature="avx2"),
                 all(target_arch="aarch64",target_feature="neon"))) {
        assert!(!cfg!(feature="native"));
        assert!(matches!(api::batch::Session::new(batch_limits()),Err(api::batch::Error::Execution(
            brynja_legacy_md5::hardened_execution::Error::Backend(brynja_legacy_md5::Md5BackendError::MissingFeatures)))));
        return Ok(());
    }
    {
        let mut session=api::batch::Session::new(batch_limits())?;
        #[cfg(target_arch="x86_64")] assert_eq!(session.backend(),brynja_legacy_md5::Md5Backend::X86Avx2);
        #[cfg(target_arch="aarch64")] assert_eq!(session.backend(),brynja_legacy_md5::Md5Backend::Aarch64Neon);
        let eligible:Vec<_>=rows().into_iter().filter(|r|r.0>=512).collect();assert_eq!(eligible.len(),89);
        let width=session.backend().lane_width();let mut lanes=0;
        for start in 0..eligible.len() {
            let chosen:[_;8]=core::array::from_fn(|i|&eligible[(start+i)%eligible.len()]);
            let inputs=chosen.map(|r|Some(api::batch::Input{bytes:&r.1,valid_bits:((r.0-1)%8+1) as u8}));
            let vector:usize=chosen.chunks(width).map(|g|width*g.iter().map(|r|r.0/512).min().unwrap()).sum();
            let total:usize=chosen.iter().map(|r|r.0/512+1+usize::from(r.0%512>=448)).sum();
            let output=session.digest(&inputs,total,&api::Cancellation::new())?;
            assert_eq!(output.report().vector_width,width);
            assert_eq!(output.report().work.vector_blocks,vector);
            assert_eq!(output.report().work.scalar_blocks,total-vector);
            assert_eq!(output.report().work.active_lanes,8);
            for (actual,r) in output.expose().chunks_exact(16).zip(chosen){assert_eq!(actual,r.2);lanes+=1;}
            let mut public=[0xa5;128];output.declassify(&mut public,api::PublicDeclassification::acknowledge())?;
            for (actual,r) in public.chunks_exact(16).zip(chosen){assert_eq!(actual,r.2);}
            assert!(!session.is_quarantined());
        }
        assert_eq!(lanes,712);
        let bytes=[0x36;128];let inputs=core::array::from_fn(|_|Some(api::batch::Input::bytes(&bytes)));
        for budget in 0..24 {
            assert!(matches!(session.digest(&inputs,budget,&api::Cancellation::new()),Err(api::batch::Error::Execution(
                brynja_legacy_md5::hardened_execution::Error::Batch(brynja_legacy_md5::Md5BatchError::WorkLimit)))));
            assert!(!session.is_quarantined());
            assert_eq!(session.digest(&inputs,24,&api::Cancellation::new())?.report().work.vector_blocks,16);
        }
        let cancelled=api::Cancellation::new();cancelled.cancel();
        assert!(matches!(session.digest(&inputs,24,&cancelled),Err(api::batch::Error::Cancelled)));
        assert!(!session.is_quarantined());
        let invalid=core::array::from_fn(|_|Some(api::batch::Input{bytes:&[1],valid_bits:1}));
        assert!(matches!(session.digest(&invalid,24,&api::Cancellation::new()),Err(api::batch::Error::InvalidBits)));
        assert!(!session.is_quarantined());
        assert!(session.digest(&[None,None,None,None,None,None,None,None],24,&api::Cancellation::new()).is_err());
        assert!(!session.is_quarantined());
        let mut wrong=[0xa5;127];
        assert_eq!(session.digest(&inputs,24,&api::Cancellation::new())?.declassify(&mut wrong,api::PublicDeclassification::acknowledge()),Err(api::batch::Error::OutputLength));
        assert_eq!(wrong,[0xa5;127]);
        std::mem::forget(session.digest(&inputs,24,&api::Cancellation::new())?);
        assert_eq!(session.digest(&inputs,24,&api::Cancellation::new())?.report().work.vector_blocks,16);
        session.quarantine();assert!(session.is_quarantined());
        assert!(matches!(session.digest(&inputs,24,&api::Cancellation::new()),Err(api::batch::Error::Quarantined)));
        println!("\nSTRICT_LEGACY_NATIVE: md5; lanes=712");
    }
    Ok(())
}
'''


def source(family):
    text = COMMON + (SHA1 if family == 'sha1' else MD5)
    for before, after in {'FAMILY': family, 'COLUMN': '2' if family == 'sha1' else '3',
                          'WIDTH': '20' if family == 'sha1' else '16',
                          'ABC': '"a9993e364706816aba3e25717850c26c9cd0d89d"' if family == 'sha1' else
                          '"900150983cd24fb0d6963f7d28e17f72"'}.items():
        text = text.replace(before, after)
    return text


def owners(family):
    return ('Session', "Digest<'static>", 'CompiledSession') if family == 'sha1' else (
        'Session', "Digest<'static>", 'batch::Session', "batch::Output<'static>")


def negatives(family):
    prefix = f'use brynja_legacy_{family}_std::strict_execution as api;\n'
    cases = [
        ('fn escape(s:&mut api::Session)->api::Digest<\'static>{s.hash(b"abc").unwrap()}', None),
        ('fn overlap(s:&mut api::Session){let a=s.hash(b"abc").unwrap();let _=s.hash(b"x");let _=a.expose();}', 'E0499'),
        ('fn public(d:api::Digest){let _=d.declassify(&mut [0;20]);}', 'E0061'),
        ('fn copy(d:api::Digest){let _=d.clone();}', 'E0599'),
        ('fn mutate(d:api::Digest){let _=d.output;}', 'E0616'),
    ]
    if family == 'sha1':
        cases += [
            ('fn escape(s:&mut api::CompiledSession)->api::Digest<\'static>{s.hash(b"abc").unwrap()}', None),
            ('fn overlap(s:&mut api::CompiledSession){let a=s.hash(b"abc").unwrap();s.quarantine();let _=a.expose();}', 'E0499'),
        ]
    else:
        cases += [
            ('fn escape(s:&mut api::batch::Session)->api::batch::Output<\'static>{s.digest(&[None,None,None,None,None,None,None,None],1,&api::Cancellation::new()).unwrap()}', None),
            ('fn overlap(s:&mut api::batch::Session){let a=s.digest(&[None,None,None,None,None,None,None,None],1,&api::Cancellation::new()).unwrap();s.quarantine();let _=a.expose();}', 'E0499'),
            ('fn public(d:api::batch::Output){let _=d.declassify(&mut [0;128]);}', 'E0061'),
        ]
    return [(prefix + text, code) for text, code in cases]


def mutations(family, native):
    cases = [
        ('worker.rs', 'state.update(part)', 'state.update(&[])', 'scalar_corpus'),
        ('mod.rs', 'destination.copy_from_slice(self.output.as_bytes());', 'let _ = destination;', 'scalar_corpus'),
        ('mod.rs', 'if destination.len() != ', 'if destination.len() == ', 'scalar_lifecycle'),
    ]
    if native and family == 'sha1':
        cases += [('compiled.rs', 'self.quarantined = true;\n        self.inner.output.clear();',
                   'self.quarantined = false;\n        self.inner.output.clear();', 'compiled_admission_and_corpus'),
                  ('compiled/worker.rs', 'state.update(part)', 'state.update(&[])', 'compiled_admission_and_corpus')]
    if native and family == 'md5':
        cases += [('batch/mod.rs', 'self.quarantined = false;', 'self.quarantined = true;', 'compiled_admission_and_corpus'),
                  ('batch/mod.rs', 'destination.copy_from_slice(self.expose());', 'let _ = destination;', 'compiled_admission_and_corpus'),
                  ('batch/worker.rs', 'brynja_core::copy_secret_region(destination, secret.expose())',
                   'brynja_core::copy_secret_region(destination, &[0;128])', 'compiled_admission_and_corpus')]
    return [('strict_execution/' + name, before, after, test) for name, before, after, test in cases]
