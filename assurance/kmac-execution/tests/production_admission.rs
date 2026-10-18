//! Runtime admission checks, including finalizers on deliberately weak test owners.
use brynja_mac_kmac::{KmacError, conformance as test};

macro_rules! fixed {
    ($api:path, $test:path, $name:ident, $size:expr $(, $mode:expr)?) => {{
        use $api as api;
        use $test as test;
        assert!(matches!(api::$name::new($($mode,)? &[], &[]), Err(KmacError::KeyTooShort)));
        let key = [7; $size];
        let mut output = [0xa5; 1];
        assert!(matches!(api::$name::new($($mode,)? &key, &[])?.finalize_tag(&mut output),
                         Err(KmacError::TagTooShort)));
        assert_eq!(output, [0xa5; 1]);
        assert!(matches!(api::$name::new($($mode,)? &key, &[])?.verify(&[0]),
                         Err(KmacError::TagTooShort)));
        // Test owners share the production finalizers but can carry weak keys.
        // This makes the otherwise unreachable finalizer key check load-bearing.
        assert!(matches!(test::$name::new_conformance($($mode,)? &[], &[])?.finalize_tag(&mut output),
                         Err(KmacError::KeyTooShort)));
        assert_eq!(output, [0xa5; 1]);
        assert!(matches!(test::$name::new_conformance($($mode,)? &[], &[])?.verify(&[0; $size]),
                         Err(KmacError::KeyTooShort)));
    }};
}

macro_rules! xof {
    ($api:path, $test:path, $name:ident, $size:expr $(, $mode:expr)?) => {{
        use $api as api;
        use $test as test;
        assert!(matches!(api::$name::new($($mode,)? &[], &[]), Err(KmacError::KeyTooShort)));
        // Portable finalization consumes self; execution finalization borrows it.
        #[allow(unused_mut)]
        let mut weak = test::$name::new_conformance($($mode,)? &[], &[])?;
        assert!(matches!(weak.finalize_xof(), Err(KmacError::KeyTooShort)));
        #[allow(unused_mut)]
        let mut valid = api::$name::new($($mode,)? &[7; $size], &[])?;
        let mut output = [0xa5; 17];
        let mut reader = valid.finalize_xof()?;
        let secret = reader.squeeze_secret(&mut output)?;
        assert_ne!(secret.expose(), &[0xa5; 17]);
        drop(secret);
        assert_eq!(output, [0; 17]);
    }};
}

macro_rules! scoped_fixed {
    ($production:expr, $conformance:expr, $size:expr) => {{
        let mut workspace = $production;
        let mut called = false;
        assert!(matches!(
            workspace.with(&[], &[], |_| called = true),
            Err(KmacError::KeyTooShort)
        ));
        assert!(!called);
        let key = [7; $size];
        let mut output = [0xa5; 1];
        assert!(workspace.with(&key, &[], |state| matches!(
            state.finalize_tag(&mut output),
            Err(KmacError::TagTooShort)
        ))?);
        assert_eq!(output, [0xa5; 1]);
        assert!(workspace.with(&key, &[], |state| matches!(
            state.verify(&[0]),
            Err(KmacError::TagTooShort)
        ))?);
        let mut weak = $conformance;
        assert!(weak.with_conformance(&[], &[], |state| matches!(
            state.finalize_tag(&mut output),
            Err(KmacError::KeyTooShort)
        ))?);
        assert_eq!(output, [0xa5; 1]);
        assert!(weak.with_conformance(&[], &[], |state| matches!(
            state.verify(&[0; $size]),
            Err(KmacError::KeyTooShort)
        ))?);
    }};
}

macro_rules! scoped_xof {
    ($production:expr, $conformance:expr, $size:expr) => {{
        let mut workspace = $production;
        let mut called = false;
        assert!(matches!(
            workspace.with(&[], &[], |_| called = true),
            Err(KmacError::KeyTooShort)
        ));
        assert!(!called);
        let mut weak = $conformance;
        assert!(weak.with_conformance(&[], &[], |state| matches!(
            state.finalize_xof(),
            Err(KmacError::KeyTooShort)
        ))?);
        let mut output = [0xa5; 17];
        workspace.with(&[7; $size], &[], |state| {
            let mut reader = state.finalize_xof()?;
            let secret = reader.squeeze_secret(&mut output)?;
            assert_ne!(secret.expose(), &[0xa5; 17]);
            drop(secret);
            Ok::<(), KmacError>(())
        })??;
        assert_eq!(output, [0; 17]);
    }};
}

#[test]
fn portable_policy() -> Result<(), KmacError> {
    use brynja_mac_kmac::hardened_in_place as scoped;
    use test::hardened_in_place as weak;
    fixed!(brynja_mac_kmac, test, Kmac128, 16);
    fixed!(brynja_mac_kmac, test, Kmac256, 32);
    xof!(brynja_mac_kmac, test, KmacXof128, 16);
    xof!(brynja_mac_kmac, test, KmacXof256, 32);
    scoped_fixed!(
        scoped::Kmac128Workspace::new(),
        weak::Kmac128Workspace::new(),
        16
    );
    scoped_fixed!(
        scoped::Kmac256Workspace::new(),
        weak::Kmac256Workspace::new(),
        32
    );
    scoped_xof!(
        scoped::KmacXof128Workspace::new(),
        weak::KmacXof128Workspace::new(),
        16
    );
    scoped_xof!(
        scoped::KmacXof256Workspace::new(),
        weak::KmacXof256Workspace::new(),
        32
    );
    Ok(())
}

fn execution_policy<'a>(
    mode: impl Fn() -> Result<brynja_mac_kmac::execution::Mode<'a>, KmacError>,
) -> Result<(), KmacError> {
    fixed!(
        brynja_mac_kmac::execution,
        test::execution,
        Kmac128,
        16,
        mode()?
    );
    fixed!(
        brynja_mac_kmac::execution,
        test::execution,
        Kmac256,
        32,
        mode()?
    );
    xof!(
        brynja_mac_kmac::execution,
        test::execution,
        KmacXof128,
        16,
        mode()?
    );
    xof!(
        brynja_mac_kmac::execution,
        test::execution,
        KmacXof256,
        32,
        mode()?
    );
    Ok(())
}

#[test]
fn execution_portable_policy() -> Result<(), KmacError> {
    execution_policy(|| Ok(brynja_mac_kmac::execution::Mode::Portable))
}

#[test]
#[ignore = "requires native compiled-target Keccak authority; packaged native gate runs explicitly"]
fn accelerated_policy() -> Result<(), KmacError> {
    use brynja_crypto_cpu::{hardened_execution::KeccakSession, static_execution as raw};
    use brynja_mac_kmac::execution::{Mode, in_place as scoped};
    use test::execution::in_place as weak;
    let kernel = if cfg!(target_arch = "x86_64") {
        raw::Kernel::X86Keccak
    } else {
        raw::Kernel::ArmKeccak
    };
    let authority = raw::Authority::new(kernel).map_err(|_| KmacError::AccelerationUnavailable)?;
    let session =
        || KeccakSession::from_static(&authority).map_err(|_| KmacError::AccelerationUnavailable);
    execution_policy(|| Ok(Mode::Require(Some(session()?))))?;
    scoped_fixed!(
        scoped::Kmac128Workspace::new(session()?)?,
        weak::Kmac128Workspace::new(session()?)?,
        16
    );
    scoped_fixed!(
        scoped::Kmac256Workspace::new(session()?)?,
        weak::Kmac256Workspace::new(session()?)?,
        32
    );
    scoped_xof!(
        scoped::KmacXof128Workspace::new(session()?)?,
        weak::KmacXof128Workspace::new(session()?)?,
        16
    );
    scoped_xof!(
        scoped::KmacXof256Workspace::new(session()?)?,
        weak::KmacXof256Workspace::new(session()?)?,
        32
    );
    assert_eq!(authority.report().health, raw::Health::Healthy);
    Ok(())
}
