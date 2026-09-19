use super::super::{Authority, Kernel, Mode};
use super::*;
use crate::hardened_in_place as portable;
use crate::{Fips202BitString, Fips202Output};
extern crate std;
mod handoff;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    vec::Vec,
};

fn cleared(workspace: &Workspace) {
    assert_eq!(workspace.values, [[0; 64]; CAPACITY]);
    assert_eq!(workspace.staging, [0; 256]);
}
fn native() -> Result<Option<Authority>, Error> {
    let kernel = if cfg!(target_arch = "aarch64") {
        Kernel::Neon
    } else {
        Kernel::Avx2
    };
    if !kernel.compiled() {
        assert!(std::env::var_os("BRYNJA_REQUIRE_PARALLELHASH_BATCH").is_none());
        return Ok(None);
    }
    Authority::for_compiled_target(kernel)
        .map(Some)
        .map_err(|e| hash::Error::Backend(e).into())
}

macro_rules! tests {
    ($campaign:ident, $plain:ident, $vector:ident, $failures:ident, $routes:ident,
     $plan:ident, $root:ident, $fixed:ident, $xof:ident, $width:expr) => {
        fn $campaign(engine: &Executor<'_>) -> Result<(), Error> {
            let mut workspace = Workspace::new();
            for block in [1usize, 7, 136, 168] {
                for length in [0, 1, block.saturating_mul(4), block.saturating_mul(4).saturating_add(1), block.saturating_mul(9)] {
                    for valid in [1, 5, 8] {
                        let mut input: Vec<_> = (0..length).map(|n| n.to_le_bytes()[0].wrapping_mul(29)).collect();
                        if let Some(last) = input.last_mut() { *last &= 0xff >> 8u8.saturating_sub(valid); }
                        let input = Fips202BitString::new(&input, if length == 0 { 0 } else { valid }).map_err(|_| RootError::State)?;
                        let plan = crate::$plan::new_bits(input, block).map_err(plan_error)?;
                        let custom = Fips202BitString::new(&[19], 5).map_err(|_| RootError::State)?;
                        for xof in [false, true] {
                            let mut expected = [0; 39];
                            let mut buffer = std::vec![0; block];
                            let out = Fips202Output::new(&mut expected, 5).map_err(|_| RootError::State)?;
                            if xof {
                                crate::$xof::new_bits(&mut buffer, custom).map_err(plan_error)?
                                    .finalize_bits_xof(input).map_err(plan_error)?
                                    .squeeze_final_bits(out).map_err(plan_error)?;
                            } else {
                                crate::$fixed::new_bits(&mut buffer, custom).map_err(plan_error)?
                                    .finalize_bits(input, out).map_err(plan_error)?;
                            }
                            let mut root = portable::$root::new();
                            root.with_bits(&plan, custom, |mut root| -> Result<(), Error> {
                                let mut start = 0;
                                let mut accelerated = 0u128;
                                while start < plan.leaf_count() {
                                    let count = usize::try_from(plan.leaf_count().checked_sub(start).ok_or(RootError::State)?.min(4)).map_err(|_|RootError::State)?;
                                    let mut slots = [[0xa5; 64]; 4];
                                    let mut no = || false;
                                    let leaves = plan.batch(start, count)?.execute_into(engine, &mut workspace,
                                        &mut slots, &mut Control::new(256, &mut no))?;
                                    let report = leaves.report();
                                    assert_eq!(report.accelerated_slots != 0, report.vector_calls != 0);
                                    accelerated = accelerated.checked_add(u128::from(report.accelerated_slots.count_ones())).ok_or(RootError::State)?;
                                    root.merge_batch(leaves).map_err(plan_error)?;
                                    assert_eq!(slots, [[0; 64]; 4]);
                                    cleared(&workspace);
                                    start = start.checked_add(count as u128).ok_or(RootError::State)?;
                                }
                                let wanted = if let Some(k) = engine.kernel()? { plan.leaf_count().checked_div(k.width() as u128).and_then(|n|n.checked_mul(k.width() as u128)).ok_or(RootError::State)? } else {0};
                                assert_eq!(accelerated, wanted);
                                let mut output = [0xa5; 39];
                                let secret = if xof {
                                    root.finalize_xof().map_err(plan_error)?.squeeze_final_bits_secret(&mut output, 5).map_err(plan_error)?
                                } else { root.finalize_secret_bits(&mut output, 5).map_err(plan_error)? };
                                assert_eq!(secret.expose(), expected);
                                drop(secret);
                                assert_eq!(output, [0; 39]);
                                Ok(())
                            }).map_err(plan_error)??;
                        }
                    }
                }
            }
            Ok(())
        }
        #[test]
        fn $plain() -> Result<(), Error> { $campaign(&Executor::portable()) }
        #[test]
        fn $vector() -> Result<(), Error> {
            let Some(owner) = native()? else { return Ok(()); };
            let engine = Executor::with_session(owner.session().map_err(hash::Error::Backend)?, Mode::Prefer, 1)?;
            $campaign(&engine)
        }
        #[test]
        fn $failures() -> Result<(), Error> {
            let plan = crate::$plan::new(b"abcdefgh", 1).map_err(plan_error)?;
            let foreign = crate::$plan::new(b"abcdefgh", 1).map_err(plan_error)?;
            for (start, count) in [(0,0), (0,5), (8,1), (u128::MAX,1)] {
                assert!(plan.batch(start,count).is_err());
            }
            let mut workspace = Workspace::new();
            let mut slots = [[0xa5;64];4];
            let engine = Executor::portable();
            for (source, start, duplicate) in [(&foreign,0,false), (&plan,1,false), (&plan,0,true)] {
                let mut root = portable::$root::new();
                root.with(&plan, b"", |mut root| -> Result<(), Error> {
                    let mut no = || false;
                    if duplicate {
                        root.merge_batch(plan.batch(0,4)?.execute_into(&engine,&mut workspace,&mut slots,&mut Control::new(64,&mut no))?).map_err(plan_error)?;
                    }
                    let leaves = source.batch(start,4)?.execute_into(&engine,&mut workspace,&mut slots,&mut Control::new(64,&mut no))?;
                    assert!(root.merge_batch(leaves).is_err());
                    let mut out = [0xa5;32];
                    assert!(root.finalize_secret(&mut out).is_err());
                    assert_eq!(out,[0;32]);
                    assert_eq!(slots,[[0;64];4]);
                    Ok(())
                }).map_err(plan_error)??;
            }
            for budget in [0,1] {
                slots.fill([0xa5;64]);
                let mut no = || false;
                assert!(plan.batch(0,4)?.execute_into(&engine,&mut workspace,&mut slots,&mut Control::new(budget,&mut no)).is_err());
                assert_eq!(slots,[[0;64];4]); cleared(&workspace);
                assert_eq!(engine.kernel()?,None);
            }
            slots.fill([0xa5;64]);
            let mut yes = || true;
            assert!(plan.batch(0,4)?.execute_into(&engine,&mut workspace,&mut slots,&mut Control::new(64,&mut yes)).is_err());
            assert_eq!(slots,[[0;64];4]); cleared(&workspace);
            let mut no = || false;
            slots.fill([0xa5;64]);
            let leaves = plan.batch(0,1)?.execute_into(&engine,&mut workspace,&mut slots,&mut Control::new(64,&mut no))?;
            assert_eq!(&leaves.output.0[0][$width..], &[0;64][$width..]);
            assert_eq!(&leaves.output.0[1..], &[[0;64];3]);
            drop(leaves); assert_eq!(slots,[[0;64];4]); cleared(&workspace);
            slots.fill([0xa5;64]);
            let result = catch_unwind(AssertUnwindSafe(|| {
                let mut panic = || panic!("cancel callback");
                let _ = plan.batch(0,4).expect("valid").execute_into(&engine,&mut workspace,&mut slots,&mut Control::new(64,&mut panic));
            }));
            assert!(result.is_err()); assert_eq!(slots,[[0;64];4]); cleared(&workspace);
            slots.fill([0xa5;64]);
            assert!(plan.batch(0,4)?.execute_into(&engine,&mut workspace,&mut slots,&mut Control::new(64,&mut no)).is_err());
            assert_eq!(slots,[[0;64];4]);
            Ok(())
        }
        #[test]
        fn $routes() -> Result<(), Error> {
            let Some(owner) = native()? else { return Ok(()); };
            let engine = Executor::with_session(owner.session().map_err(hash::Error::Backend)?, Mode::Require, 1)?;
            let plan = crate::$plan::new(b"abcdefgh", 1).map_err(plan_error)?;
            let mut workspace = Workspace::new();
            let mut slots = [[0xa5;64];4];
            let mut no = || false;
            assert!(plan.batch(0,1)?.execute_into(&engine,&mut workspace,&mut slots,&mut Control::new(64,&mut no)).is_err());
            assert_eq!(slots,[[0;64];4]); cleared(&workspace);
            let leaves = plan.batch(0,4)?.execute_into(&engine,&mut workspace,&mut slots,&mut Control::new(64,&mut no))?;
            assert_eq!(leaves.report().accelerated_slots,15);
            assert!(leaves.report().vector_calls > 0);
            drop(leaves);
            owner.quarantine(); slots.fill([0xa5;64]);
            workspace.values.fill([0xa5;64]); workspace.staging.fill(0xa5);
            assert!(plan.batch(0,4)?.execute_into(&engine,&mut workspace,&mut slots,&mut Control::new(64,&mut no)).is_err());
            assert_eq!(slots,[[0;64];4]); cleared(&workspace);
            Ok(())
        }
    };
}
tests!(
    campaign128,
    scoped_batch_portable128,
    scoped_batch_vector128,
    scoped_batch_failures128,
    scoped_batch_routes128,
    ParallelHash128Plan,
    ParallelHash128CollectorWorkspace,
    ParallelHash128,
    ParallelHashXof128,
    32
);
tests!(
    campaign256,
    scoped_batch_portable256,
    scoped_batch_vector256,
    scoped_batch_failures256,
    scoped_batch_routes256,
    ParallelHash256Plan,
    ParallelHash256CollectorWorkspace,
    ParallelHash256,
    ParallelHashXof256,
    64
);
