//! Ordinary-host release smoke test: no emulator, forced backend or timing run.
#![cfg(feature = "ghash-runtime-execution")]

use brynja_crypto::ghash::{Backend, Error, Ghash, Mode};

#[test]
fn explicit_route_agrees_with_the_portable_default() -> Result<(), Error> {
    let key = (1_u128 << 127).to_be_bytes();
    let (mut work, mut output) = ([0x51; 16], [0; 16]);
    let mut portable = Ghash::new(&key, &mut work, 16);
    assert_eq!(portable.backend(), Backend::Portable);
    portable.update(&[0x69; 16])?;
    let answer = [0x69; 16];
    assert_eq!(portable.finish(&mut output)?.expose(), answer);

    let mut preferred = Ghash::new_with_backend(&key, &mut work, 16, Mode::Prefer)?;
    let backend = preferred.backend();
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    assert_eq!(
        backend == Backend::Pclmul,
        std::is_x86_feature_detected!("sse2") && std::is_x86_feature_detected!("pclmulqdq")
    );
    preferred.update(&[0x69; 16])?;
    assert_eq!(preferred.finish(&mut output)?.expose(), answer);

    work.fill(0x51);
    if backend == Backend::Portable {
        assert_eq!(
            Ghash::new_with_backend(&key, &mut work, 16, Mode::Require).err(),
            Some(Error::Unavailable)
        );
        assert_eq!(work, [0x51; 16]);
    } else {
        let mut required = Ghash::new_with_backend(&key, &mut work, 16, Mode::Require)?;
        assert_eq!(required.backend(), backend);
        required.update(&[0x69; 16])?;
        assert_eq!(required.finish(&mut output)?.expose(), answer);
    }
    Ok(())
}
