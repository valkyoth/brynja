use super::*;
use crate::ParallelHashPublicDeclassification as Public;
use crate::execution::{KeccakSession, in_place as accelerated};
use brynja_crypto_cpu::static_execution as cpu;

macro_rules! handoff {
    ($test:ident, $plan:ident, $root:ident) => {
        #[test]
        fn $test() -> Result<(), Error> {
            let plan = crate::$plan::new(b"abcdefgh", 1).map_err(plan_error)?;
            let mut slots = [[0xa5; 64]; 4];
            // Worker-local authority and workspace; only a completed loan joins.
            let leaves = std::thread::scope(|scope| {
                scope
                    .spawn(|| -> Result<_, Error> {
                        let owner = native()?;
                        let engine = match &owner {
                            Some(owner) => Executor::with_session(
                                owner.session().map_err(hash::Error::Backend)?,
                                Mode::Require,
                                1,
                            )?,
                            None => Executor::portable(),
                        };
                        let mut workspace = Workspace::new();
                        let mut no = || false;
                        plan.batch(0, 4)?.execute_into(
                            &engine,
                            &mut workspace,
                            &mut slots,
                            &mut Control::new(64, &mut no),
                        )
                    })
                    .join()
                    .expect("worker joined")
            })?;
            let mut root = portable::$root::new();
            root.with(&plan, b"", |mut root| -> Result<(), Error> {
                root.merge_batch(leaves).map_err(plan_error)?;
                let mut bytes = [0xa5; 32];
                assert!(
                    root.finalize_public(&mut bytes, Public::acknowledge())
                        .is_err()
                );
                assert_eq!(bytes, [0xa5; 32]);
                Ok(())
            })
            .map_err(plan_error)??;
            assert_eq!(slots, [[0; 64]; 4]);

            let kernel = if cfg!(target_arch = "aarch64") {
                cpu::Kernel::ArmKeccak
            } else {
                cpu::Kernel::X86Keccak
            };
            let owner = match cpu::Authority::new(kernel) {
                Ok(owner) => owner,
                Err(cpu::Error::MissingTargetFeatures | cpu::Error::WrongArchitecture) => {
                    assert!(std::env::var_os("BRYNJA_REQUIRE_SCOPED_PARALLEL").is_none());
                    return Ok(());
                }
                Err(_) => return Err(RootError::State.into()),
            };
            let session = KeccakSession::from_static(&owner).map_err(|_| RootError::State)?;
            let mut root = accelerated::$root::new(session).map_err(plan_error)?;
            let mut workspace = Workspace::new();
            let mut no = || false;
            let mut expected = [0; 32];
            let mut reference = portable::$root::new();
            reference
                .with(&plan, b"", |mut root| -> Result<(), Error> {
                    for start in [0, 4] {
                        root.merge_batch(plan.batch(start, 4)?.execute_into(
                            &Executor::portable(),
                            &mut workspace,
                            &mut slots,
                            &mut Control::new(64, &mut no),
                        )?)
                        .map_err(plan_error)?;
                    }
                    root.finalize_public(&mut expected, Public::acknowledge())
                        .map_err(plan_error)
                })
                .map_err(plan_error)??;
            root.with(&plan, b"", |mut root| -> Result<(), Error> {
                for start in [0, 4] {
                    root.merge_batch(plan.batch(start, 4)?.execute_into(
                        &Executor::portable(),
                        &mut workspace,
                        &mut slots,
                        &mut Control::new(64, &mut no),
                    )?)
                    .map_err(plan_error)?;
                }
                let mut output = [0xa5; 32];
                root.finalize_public(&mut output, Public::acknowledge())
                    .map_err(plan_error)?;
                assert_eq!(output, expected);
                Ok(())
            })
            .map_err(plan_error)??;
            root.with(&plan, b"", |mut root| -> Result<(), Error> {
                let leaves = plan.batch(0, 4)?.execute_into(
                    &Executor::portable(),
                    &mut workspace,
                    &mut slots,
                    &mut Control::new(64, &mut no),
                )?;
                owner.quarantine();
                assert!(root.merge_batch(leaves).is_err());
                assert_eq!(slots, [[0; 64]; 4]);
                let mut output = [0xa5; 32];
                assert!(root.finalize_secret(&mut output).is_err());
                assert_eq!(output, [0; 32]);
                Ok(())
            })
            .map_err(plan_error)??;
            Ok(())
        }
    };
}
handoff!(
    scoped_batch_handoff128,
    ParallelHash128Plan,
    ParallelHash128CollectorWorkspace
);
handoff!(
    scoped_batch_handoff256,
    ParallelHash256Plan,
    ParallelHash256CollectorWorkspace
);
