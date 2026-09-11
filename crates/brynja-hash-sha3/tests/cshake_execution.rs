//! Ordinary cSHAKE portable and required target-specialized acceptance.
#![cfg(feature = "static-execution")]
mod cshake_execution_cases;
use brynja_hash_sha3::execution as api;
use cshake_execution_cases as cases;

#[test]
fn portable_cshake_execution_vectors() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(cases::run(|| Ok(api::Execution::portable()))?, 628);
    Ok(())
}

#[test]
fn required_cshake_static_route_if_compiled() -> Result<(), Box<dyn std::error::Error>> {
    let kernel = if cfg!(target_arch = "aarch64") {
        api::Kernel::ArmKeccak
    } else {
        api::Kernel::X86Keccak
    };
    let compiled = cfg!(all(
        target_arch = "x86_64",
        target_feature = "avx",
        target_feature = "avx2"
    )) || cfg!(all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_feature = "sha3"
    ));
    if compiled {
        let owner = api::StaticSelection::new(kernel, api::Mode::Require)?;
        assert_eq!(cases::run(|| Ok(owner.execution()?))?, 628);
        let mut reader = api::Cshake256::new(
            owner.execution()?,
            api::Public::new(b""),
            api::Public::new(b"S"),
        )?
        .finalize_xof()?;
        owner.quarantine();
        let mut output = [0xa5; 2];
        assert!(reader.squeeze(&mut output).is_err());
        assert_eq!(output, [0xa5; 2]);
        assert!(owner.execution().is_err());
    }
    Ok(())
}
