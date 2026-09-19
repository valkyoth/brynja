//! Ordered scoped collectors clear borrowed storage through recoverable unwind.
use brynja_hash_parallel::{
    self as hash, ParallelHashError as Error, ParallelHashPublicDeclassification as Public,
    hardened_in_place as api,
};
use std::panic::{AssertUnwindSafe, catch_unwind};

macro_rules! check {
    ($test:ident, $plan:ident, $workspace:ident, $width:expr) => {
        #[test]
        fn $test() -> Result<(), Error> {
            let plan = hash::$plan::new(b"input spans several leaves", 8)?;
            let mut workspace = api::$workspace::new();
            for mode in 0..3 {
                let mut leaf = [0xa5; $width];
                let caught = catch_unwind(AssertUnwindSafe(|| {
                    let _: Result<Result<(), Error>, Error> =
                        workspace.with(&plan, b"", |mut root| {
                            root.merge(plan.job(0)?.execute(&mut leaf)?)?;
                            if mode == 0 {
                                panic!("collector unwind");
                            }
                            for index in 1..plan.leaf_count() {
                                root.merge(plan.job(index)?.execute(&mut leaf)?)?;
                            }
                            let mut reader = root.finalize_xof()?;
                            drop(reader.squeeze_secret(&mut [0xa5; 179])?);
                            if mode == 1 {
                                panic!("reader unwind");
                            }
                            core::mem::forget(reader);
                            Ok(())
                        });
                }));
                assert_eq!(caught.is_err(), mode != 2);
                assert_eq!(leaf, [0; $width]);
                let mut actual = [0xa5; 32];
                let mut expected = [0; 32];
                for (owner, output) in [
                    (&mut workspace, &mut actual),
                    (&mut api::$workspace::new(), &mut expected),
                ] {
                    owner.with(&plan, b"", |mut root| {
                        for index in 0..plan.leaf_count() {
                            root.merge(plan.job(index)?.execute(&mut leaf)?)?;
                        }
                        root.finalize_public(output, Public::acknowledge())
                    })??;
                }
                assert_eq!(actual, expected);
                assert_ne!(actual, [0xa5; 32]);
            }
            // Computation may be scheduled out of order while merge remains ordered.
            let plan = hash::$plan::new(b"two leaves", 8)?;
            let mut first = [0; $width];
            let mut last = [0; $width];
            let second = plan.job(1)?.execute(&mut last)?;
            let initial = plan.job(0)?.execute(&mut first)?;
            workspace.with(&plan, b"", |mut root| {
                root.merge(initial)?;
                root.merge(second)?;
                root.finalize_public(&mut [0; 32], Public::acknowledge())
            })??;
            assert_eq!(first, [0; $width]);
            assert_eq!(last, [0; $width]);
            Ok(())
        }
    };
}
check!(
    scoped_scheduled128_unwind_reuse,
    ParallelHash128Plan,
    ParallelHash128CollectorWorkspace,
    32
);
check!(
    scoped_scheduled256_unwind_reuse,
    ParallelHash256Plan,
    ParallelHash256CollectorWorkspace,
    64
);
