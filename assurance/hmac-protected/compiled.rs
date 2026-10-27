use brynja_crypto_cpu_std::strict_hmac::*;
use brynja_mac_hmac as mac;

fn run<A: Algorithm + for<'a> mac::execution::Algorithm<'a>>(kernel: Kernel) -> Result<(), Error> {
    let limits = Limits {
        stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
        max_buffer_mapping_bytes: 65536, max_key_bytes: 4096,
        max_message_bits: 65536, max_chunks: 8,
    };
    let mut session = CompiledSession::<A>::new(TagPolicy::Full, kernel, limits)?;
    let key = [0x42; 257];
    let mut expected = vec![0; A::TAG_BYTES];
    let mut portable = mac::Hmac::<A>::new(&key).map_err(Error::Mac)?;
    portable.update(b"packaged").map_err(Error::Mac)?;
    let _ = portable.finalize_tag(&mut expected).map_err(Error::Mac)?;
    let output = session.authenticate(&key, b"packaged")?;
    assert_eq!(output.expose(), expected);
    drop(output);
    assert_eq!(session.verify(Request { key: &key, chunks: &[b"packaged"], tail: Bits::empty() },
                           &expected, &Cancellation::new()), Ok(()));
    session.quarantine();
    assert!(matches!(session.authenticate(&key, b"packaged"), Err(Error::Quarantined)));
    Ok(())
}
#[test]
fn compiled_extracted_consumer() -> Result<(), Error> {
    let arm = cfg!(target_arch = "aarch64");
    let kernel = std::env::var("BRYNJA_HMAC_PROTECTED_KERNEL").map_err(|_| Error::Invariant)?;
    match kernel.as_str() {
        "sha256" => {
            let k = if arm { Kernel::ArmSha256 } else { Kernel::X86Sha256 };
            run::<Sha224>(k)?; run::<Sha256>(k)?;
        }
        "sha512" => {
            let k = if arm { Kernel::ArmSha512 } else { Kernel::X86Sha512 };
            run::<Sha384>(k)?; run::<Sha512>(k)?; run::<Sha512_224>(k)?;
            run::<Sha512_256>(k)?; run::<Sha512T<129>>(k)?; run::<Sha512T<511>>(k)?;
        }
        "keccak" => {
            let k = if arm { Kernel::ArmKeccak } else { Kernel::X86Keccak };
            run::<Sha3_224>(k)?; run::<Sha3_256>(k)?; run::<Sha3_384>(k)?; run::<Sha3_512>(k)?;
        }
        _ => return Err(Error::Invariant),
    }
    Ok(())
}
