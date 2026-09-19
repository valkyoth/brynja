use super::*;
use crate::execution::batch::{Control, Executor, Workspace};
use crate::execution::{Collector, Identity, Mode};
#[test]
fn transfer_clears_source_and_all_transport_capacity() -> Result<(), Error> {
    for identity in [Identity::ParallelHash128, Identity::ParallelHash256] {
        let plan = Plan::new(identity, b"abcd", 1, 4)?;
        let mut workspace = Workspace::new();
        let mut slots = [[0xa5; 64]; CAPACITY];
        let mut no = || false;
        let leaves = plan.batch(0, 3)?.execute(
            &Executor::portable(),
            &mut workspace,
            &mut Control::new(16, &mut no),
        )?;
        // Test-only snapshot: source and transport must agree, not just clear.
        let mut expected = [[0; 64]; CAPACITY];
        for (index, out) in expected.iter_mut().enumerate().take(3) {
            let source = leaves.inner.expose(index).ok_or(RootError::State)?;
            out.get_mut(..source.len())
                .ok_or(RootError::State)?
                .copy_from_slice(source);
        }
        let transfer = leaves.transfer(&mut slots)?;
        assert_eq!(*transfer.values, expected);
        assert_eq!(workspace.values, [[0; 64]; CAPACITY]);
        assert_eq!(workspace.staging, [0; 256]);
        assert_eq!(transfer.len(), 3);
        assert!(!transfer.is_empty());
        assert_eq!(transfer.values[3], [0; 64]);
        if identity == Identity::ParallelHash128 {
            assert!(
                transfer
                    .values
                    .iter()
                    .all(|v| v[32..].iter().all(|v| *v == 0))
            );
        }
        drop(transfer);
        assert_eq!(slots, [[0; 64]; CAPACITY]);
    }
    Ok(())
}
#[test]
fn rejected_transfer_clears_partial_transport_and_originals() -> Result<(), Error> {
    for identity in [Identity::ParallelHash128, Identity::ParallelHash256] {
        let plan = Plan::new(identity, b"abcd", 1, 4)?;
        let mut workspace = Workspace::new();
        let mut slots = [[0xa5; 64]; CAPACITY];
        let mut no = || false;
        let mut leaves = plan.batch(0, 3)?.execute(
            &Executor::portable(),
            &mut workspace,
            &mut Control::new(16, &mut no),
        )?;
        // The first three values are valid; the final missing source must cause
        // both guards to clear even after earlier secret transfers succeeded.
        leaves.count = 4;
        assert!(matches!(
            leaves.transfer(&mut slots),
            Err(Error::Root(RootError::State))
        ));
        assert_eq!(slots, [[0; 64]; CAPACITY]);
        assert_eq!(workspace.values, [[0; 64]; CAPACITY]);
        assert_eq!(workspace.staging, [0; 256]);
    }
    Ok(())
}
#[test]
fn transferred_tokens_preserve_plan_and_order_and_clear_on_rejection() -> Result<(), Error> {
    let plan = Plan::new(Identity::ParallelHash128, b"abcd", 1, 4)?;
    let foreign = Plan::new(Identity::ParallelHash128, b"abcd", 1, 4)?;
    for (source, start, duplicate) in [(&foreign, 0, false), (&plan, 1, false), (&plan, 0, true)] {
        let mut workspace = Workspace::new();
        let mut slots = [[0xa5; 64]; CAPACITY];
        let mut no = || false;
        let mut control = Control::new(32, &mut no);
        let executor = Executor::portable();
        let mut root = Collector::new(&plan, Mode::Portable, b"")?;
        if duplicate {
            root.merge_transferred(
                plan.batch(0, 1)?
                    .execute(&executor, &mut workspace, &mut control)?
                    .transfer(&mut slots)?,
            )?;
        }
        let token = source
            .batch(start, 1)?
            .execute(&executor, &mut workspace, &mut control)?
            .transfer(&mut slots)?;
        assert!(root.merge_transferred(token).is_err());
        assert_eq!(slots, [[0; 64]; CAPACITY]);
        let mut output = [0xa5; 32];
        assert!(root.finalize_secret(&mut output).is_err());
        assert_eq!(output, [0; 32]);
    }
    Ok(())
}
