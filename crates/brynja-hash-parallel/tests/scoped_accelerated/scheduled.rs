use super::*;

macro_rules! check {
    ($test:ident, $workspace:ident, $leaf_workspace:ident, $plan:ident, $fixed:ident, $xof:ident, $size:expr) => {
        #[test]
        fn $test() -> Result<(), Box<dyn std::error::Error>> {
            let Some(root_owner) = owner()? else {
                return Ok(());
            };
            let Some(leaf_owner) = owner()? else {
                return Ok(());
            };
            let run = || -> Result<(), Error> {
                let mut workspace = api::$workspace::new(session(&root_owner)?)?;
                let mut leaf_worker = api::$leaf_workspace::new(session(&leaf_owner)?)?;
                assert_eq!(workspace.report().kernel, root_owner.report().kernel);
                assert_eq!(leaf_worker.report().kernel, leaf_owner.report().kernel);
                for b in [1, 8, 17, 168] {
                    for valid in 1..=8 {
                        let input = [1; 35];
                        let bits = Fips202BitString::new(&input, valid)
                            .map_err(|_| Error::InvalidBitString)?;
                        let custom =
                            Fips202BitString::new(&[3], 2).map_err(|_| Error::InvalidBitString)?;
                        let plan = hash::$plan::new_bits(bits, b)?;
                        let mut output = [0xa5; 259];
                        let mut scratch = [0xa5; 300];
                        let mut expected = [0; 259];
                        let mut storage = [0; 168];
                        let block = storage.get_mut(..b).ok_or(Error::StateConsumed)?;
                        hash::$fixed::new_bits(block, custom)?.finalize_bits(
                            bits,
                            Fips202Output::new(&mut expected, valid)
                                .map_err(|_| Error::InvalidBitString)?,
                        )?;
                        workspace.with_bits_and_scratch(
                            &plan,
                            custom,
                            &mut scratch,
                            |mut root| {
                                let mut leaf = [0xa5; $size];
                                for index in 0..plan.leaf_count() {
                                    root.merge(leaf_worker.execute(plan.job(index)?, &mut leaf)?)?;
                                    assert_eq!(leaf, [0; $size]);
                                }
                                root.finalize_public_bits(&mut output, valid, Public::acknowledge())
                            },
                        )??;
                        assert_eq!(output, expected);
                        assert_eq!(scratch, [0; 300]);
                        let secret = workspace.with_bits(&plan, custom, |mut root| {
                            let mut leaf = [0; $size];
                            for index in 0..plan.leaf_count() {
                                root.merge(leaf_worker.execute(plan.job(index)?, &mut leaf)?)?;
                            }
                            root.finalize_secret_bits(&mut output, valid)
                        })??;
                        assert_eq!(secret.expose(), expected);
                        drop(secret);
                        assert_eq!(output, [0; 259]);
                        hash::$xof::new_bits(block, custom)?
                            .finalize_bits_xof(bits)?
                            .squeeze_final_bits(
                                Fips202Output::new(&mut expected, valid)
                                    .map_err(|_| Error::InvalidBitString)?,
                            )?;
                        let (prefix, tail) = output.split_at_mut(169);
                        let secret = workspace.with_bits_and_scratch(
                            &plan,
                            custom,
                            &mut scratch,
                            |mut root| {
                                let mut leaf = [0; $size];
                                for index in 0..plan.leaf_count() {
                                    root.merge(leaf_worker.execute(plan.job(index)?, &mut leaf)?)?;
                                }
                                let mut reader = root.finalize_xof()?;
                                reader.squeeze_public(prefix, Public::acknowledge())?;
                                reader.squeeze_final_bits_secret(tail, valid)
                            },
                        )??;
                        assert_eq!(prefix, expected.get(..169).ok_or(Error::StateConsumed)?);
                        assert_eq!(
                            secret.expose(),
                            expected.get(169..).ok_or(Error::StateConsumed)?
                        );
                        drop(secret);
                        assert_eq!(tail, &[0; 90]);
                        assert_eq!(scratch, [0; 300]);
                    }
                }
                let plan = hash::$plan::new(b"two leaves", 8)?;
                let mut first = [0; $size];
                let mut last = [0; $size];
                let second = leaf_worker.execute(plan.job(1)?, &mut last)?;
                let initial = leaf_worker.execute(plan.job(0)?, &mut first)?;
                let mut expected = [0; 32];
                workspace.with(&plan, b"", |mut root| {
                    root.merge(initial)?;
                    root.merge(second)?;
                    root.finalize_public(&mut expected, Public::acknowledge())
                })??;
                assert_eq!(first, [0; $size]);
                assert_eq!(last, [0; $size]);
                // Mixed execution is explicit caller selection, not fallback.
                let mut output = [0xa5; 32];
                let mut portable = hash::hardened_in_place::$workspace::new();
                portable.with(&plan, b"", |mut root| {
                    for index in 0..plan.leaf_count() {
                        root.merge(leaf_worker.execute(plan.job(index)?, &mut first)?)?;
                    }
                    root.finalize_public(&mut output, Public::acknowledge())
                })??;
                assert_eq!(output, expected);
                workspace.with(&plan, b"", |mut root| {
                    for index in 0..plan.leaf_count() {
                        root.merge(plan.job(index)?.execute(&mut first)?)?;
                    }
                    root.finalize_public(&mut output, Public::acknowledge())
                })??;
                assert_eq!(output, expected);
                // Both workspaces may bind the same supplied authority.
                let mut same = api::$leaf_workspace::new(session(&root_owner)?)?;
                workspace.with(&plan, b"", |mut root| {
                    for index in 0..plan.leaf_count() {
                        root.merge(same.execute(plan.job(index)?, &mut first)?)?;
                    }
                    root.finalize_public(&mut output, Public::acknowledge())
                })??;
                assert_eq!(output, expected);
                Ok(())
            };
            run().map_err(|e| format!("scoped scheduled acceleration: {e:?}"))?;
            println!("SCOPED_PARALLELHASH_SCHEDULED: {}", stringify!($workspace));
            Ok(())
        }
    };
}
check!(
    scoped_scheduled_accelerated128_matches,
    ParallelHash128CollectorWorkspace,
    ParallelHash128LeafWorkspace,
    ParallelHash128Plan,
    ParallelHash128,
    ParallelHashXof128,
    32
);
check!(
    scoped_scheduled_accelerated256_matches,
    ParallelHash256CollectorWorkspace,
    ParallelHash256LeafWorkspace,
    ParallelHash256Plan,
    ParallelHash256,
    ParallelHashXof256,
    64
);
