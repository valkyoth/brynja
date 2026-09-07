//! Packaged downstream consumer: no workspace-path or execution-admission shortcut.
#[test]
fn ordered_batch_hardened_output_and_host_rejection() -> Result<(),Box<dyn std::error::Error>> {
    use brynja_legacy_md5::{BitString,Md5Batch,Md5BatchControl,HardenedMd5Batch,Md5BackendSession,Md5BackendError};
    use brynja_legacy_md5_std::RuntimeMd5Backend;
    assert!(matches!(Md5BackendSession::for_compiled_target().err(),Some(Md5BackendError::NotAdmitted|Md5BackendError::MissingFeatures)));
    assert!(RuntimeMd5Backend::required().is_err());
    let bits=BitString::new(b"abc",8).map_err(|_| "invalid bits")?;
    let inputs=[Some(bits);8];
    let expected=[0x90,0x01,0x50,0x98,0x3c,0xd2,0x4f,0xb0,0xd6,0x96,0x3f,0x7d,0x28,0xe1,0x7f,0x72];
    let mut output=[[0;16];8];
    Md5Batch::new().digest(&inputs,&mut output,&mut Md5BatchControl::new(8))?;
    assert_eq!(output,[expected;8]);
    RuntimeMd5Backend::opportunistic().batch(&inputs,&mut output,&mut Md5BatchControl::new(8))?;
    assert_eq!(output,[expected;8]);
    {
        let (secret,report)=HardenedMd5Batch::new().digest_secret(&inputs,&mut output,&mut Md5BatchControl::new(8))?;
        assert_eq!(secret.expose(),[expected;8].as_flattened());
        assert_eq!(report.active_lanes,8);
        assert_eq!(report.vector_blocks,0);
    }
    assert_eq!(output,[[0;16];8]);
    Ok(())
}
