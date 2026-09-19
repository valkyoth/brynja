use brynja_hash_parallel::{
    ParallelHashError, ParallelHashPublicDeclassification as Public, hardened_in_place as api,
};
use std::panic::{AssertUnwindSafe, catch_unwind};

macro_rules! check {
    ($test:ident, $workspace:ident) => {
        #[test]
        fn $test() -> Result<(), ParallelHashError> {
            let mut workspace = api::$workspace::new();
            for action in 0..3 {
                let mut block = [0xa5; 8];
                let result = catch_unwind(AssertUnwindSafe(|| {
                    workspace.with(&mut block, b"", |mut state| {
                        state.update(b"secret pending input")?;
                        match action {
                            0 => state.cancel(),
                            1 => core::mem::forget(state),
                            _ => panic!("injected scope unwind"),
                        }
                        Ok::<(), ParallelHashError>(())
                    })
                }));
                if action == 2 {
                    assert!(result.is_err());
                } else {
                    assert!(matches!(result, Ok(Ok(Ok(())))));
                }
                assert_eq!(block, [0; 8]);
                let mut output = [0xa5; 32];
                workspace.with(&mut block, b"", |mut state| {
                    state.update(b"fresh")?;
                    state.finalize_public(&mut output, Public::acknowledge())
                })??;
                let mut expected = [0; 32];
                // The matching strength's ordinary reference is checked by the oracle;
                // here two fresh scopes prove old partial input is not retained.
                workspace.with(&mut block, b"", |mut state| {
                    state.update(b"fresh")?;
                    state.finalize_public(&mut expected, Public::acknowledge())
                })??;
                assert_eq!(output, expected);
                assert_ne!(output, [0xa5; 32]);
            }
            Ok(())
        }
    };
}
check!(scoped_parallel128_unwind_reuse, ParallelHash128Workspace);
check!(scoped_parallel256_unwind_reuse, ParallelHash256Workspace);

macro_rules! xof {
    ($test:ident, $workspace:ident) => {
        #[test]
        fn $test() -> Result<(), ParallelHashError> {
            let mut workspace = api::$workspace::new();
            for action in 0..4 {
                let mut block = [0xa5; 8];
                let result = catch_unwind(AssertUnwindSafe(|| {
                    workspace.with(&mut block, b"", |mut state| {
                        state.update(b"secret pending input")?;
                        if action == 0 {
                            core::mem::forget(state);
                        } else {
                            let mut reader = state.finalize_xof()?;
                            drop(reader.squeeze_secret(&mut [0xa5; 169])?);
                            match action {
                                1 => core::mem::forget(reader),
                                2 => reader.cancel(),
                                _ => panic!("injected reader unwind"),
                            }
                        }
                        Ok::<(), ParallelHashError>(())
                    })
                }));
                if action == 3 {
                    assert!(result.is_err());
                } else {
                    assert!(matches!(result, Ok(Ok(Ok(())))));
                }
                assert_eq!(block, [0; 8]);
                let mut output = [0xa5; 32];
                workspace.with(&mut block, b"", |mut state| {
                    state.update(b"fresh")?;
                    state.finalize_xof()?.squeeze_final_bits_public(
                        &mut output,
                        8,
                        Public::acknowledge(),
                    )
                })??;
                let mut fresh = api::$workspace::new();
                let mut expected = [0; 32];
                fresh.with(&mut block, b"", |mut state| {
                    state.update(b"fresh")?;
                    state.finalize_xof()?.squeeze_final_bits_public(
                        &mut expected,
                        8,
                        Public::acknowledge(),
                    )
                })??;
                assert_eq!(output, expected);
                assert_ne!(output, [0xa5; 32]);
            }
            Ok(())
        }
    };
}
xof!(
    scoped_parallel_xof128_reader_unwind_reuse,
    ParallelHashXof128Workspace
);
xof!(
    scoped_parallel_xof256_reader_unwind_reuse,
    ParallelHashXof256Workspace
);
