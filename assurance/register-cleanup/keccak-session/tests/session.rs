#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod observer;

#[test]
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[cfg_attr(
    not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "sha3")
    )),
    ignore = "requires native AVX2 or native/emulated NEON/SHA3; not evidence otherwise"
)]
fn session_transfers_do_not_refill_vectors_with_state()
-> Result<(), brynja_crypto_cpu::static_execution::Error> {
    use brynja_crypto_cpu::{
        hardened_execution::KeccakSession,
        static_execution::{Authority, Kernel, PublicData},
    };
    let kernel = if cfg!(target_arch = "x86_64") {
        Kernel::X86Keccak
    } else {
        Kernel::ArmKeccak
    };
    let owner = Authority::new(kernel)?;
    let ordinary = owner.session()?;
    let mut session = KeccakSession::from_static(&owner)?;
    let mut seed = 0x6a09_e667_f3bc_c908_u64;
    for _ in 0..128 {
        let mut state = [0; 200];
        for byte in &mut state {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *byte = seed.to_le_bytes()[0];
        }
        let mut expected = core::array::from_fn(|i| {
            let mut bytes = [0; 8];
            bytes.copy_from_slice(&state[i * 8..i * 8 + 8]);
            u64::from_le_bytes(bytes)
        });
        ordinary.permute_keccak(PublicData::new(&mut expected))?;
        let (status, vectors) = observer::capture(&mut session, &mut state);
        assert_eq!(status, 0);
        assert!(
            observer::only_cleanup_metadata(&vectors),
            "unexpected vector contents at session return"
        );
        for (bytes, word) in state.as_chunks::<8>().0.iter().zip(expected) {
            assert_eq!(u64::from_le_bytes(*bytes), word);
        }
    }
    let mut control = [0; 200];
    let (status, vectors) = observer::capture_with(observer::poisoned, &mut session, &mut control);
    assert_eq!(status, 0);
    assert_eq!(
        &vectors[..16],
        &[255; 16],
        "observer missed deliberate residue"
    );
    assert!(!observer::only_cleanup_metadata(&vectors));
    let (status, vectors) = observer::capture_with(observer::reloaded, &mut session, &mut control);
    assert_eq!(status, 0);
    assert_eq!(&vectors[..16], &control[..16]);
    assert!(
        !observer::only_cleanup_metadata(&vectors),
        "observer missed output reload"
    );
    owner.quarantine();
    let mut state = [0xa5; 200];
    let (status, _) = observer::capture(&mut session, &mut state);
    assert_eq!(status, 1);
    assert_eq!(state, [0xa5; 200]);
    println!(
        "KECCAK_SESSION: 128 public calls; exact vector metadata, two residue controls and quarantine: PASS"
    );
    Ok(())
}
