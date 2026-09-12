use brynja_hash_parallel::{
    ParallelHashPublicDeclassification as Public,
    execution::{Collector, Error, Identity, Mode, Plan},
};

pub(super) fn check(
    identity: u8,
    input: &[u8],
    block: usize,
    custom: &[u8],
    expected: &str,
) -> Result<(), Error> {
    let identity = match identity {
        0 => Identity::ParallelHash128,
        1 => Identity::ParallelHash256,
        2 => Identity::ParallelHashXof128,
        3 => Identity::ParallelHashXof256,
        _ => return Err(Error::State),
    };
    campaign(identity, input, block, custom, expected, || {
        Ok(Mode::Portable)
    })?;
    #[cfg(feature = "runtime-execution")]
    {
        use brynja_crypto_cpu::{hardened_execution::KeccakSession, static_execution::Kernel};
        use brynja_crypto_cpu_std::execution::{Authority, Mode as Hosted};
        let kernel = if cfg!(target_arch = "x86_64") {
            Kernel::X86Keccak
        } else {
            Kernel::ArmKeccak
        };
        let owner = Authority::new(kernel, Hosted::Prefer).map_err(|_| Error::State)?;
        if owner.session().map_err(|_| Error::State)?.is_some() {
            campaign(identity, input, block, custom, expected, || {
                let session = owner
                    .session()
                    .map_err(|_| Error::State)?
                    .ok_or(Error::AccelerationUnavailable)?;
                let hardened = KeccakSession::from_runtime(session).map_err(|error| {
                    Error::Execution(brynja_hash_sha3::hardened_execution::Error::Backend(error))
                })?;
                Ok(Mode::Require(Some(hardened)))
            })?;
        }
    }
    Ok(())
}

fn campaign<'a>(
    identity: Identity,
    input: &[u8],
    block: usize,
    custom: &[u8],
    expected: &str,
    select: impl Fn() -> Result<Mode<'a>, Error>,
) -> Result<(), Error> {
    let plan = Plan::new(identity, input, block, 128)?;
    for scheduled in [false, true] {
        let mut root = Collector::new(&plan, select()?, custom)?;
        let accelerated = root.report().is_some();
        if scheduled {
            let mut slot = [0xa5; 64];
            for index in 0..plan.leaf_count() {
                let output = slot.get_mut(..identity.leaf_bytes()).ok_or(Error::State)?;
                let leaf = plan.job(index)?.execute(select()?, output)?;
                root.merge(&leaf)?;
            }
        } else {
            root.execute_serial(|_| select())?;
        }
        assert_eq!(
            root.accelerated_leaves(),
            if accelerated { plan.leaf_count() } else { 0 }
        );
        let mut output = [0xa5; 64];
        let mut scratch = [0xa5; 72];
        let output = output
            .get_mut(..identity.leaf_bytes())
            .ok_or(Error::State)?;
        if matches!(
            identity,
            Identity::ParallelHashXof128 | Identity::ParallelHashXof256
        ) {
            root.finalize_xof()?.squeeze_final_public(
                output,
                8,
                &mut scratch,
                Public::acknowledge(),
            )?;
        } else {
            root.finalize_public(output, &mut scratch, Public::acknowledge())?;
        }
        super::assert_hex(output, expected);
        assert_eq!(scratch, [0; 72]);
    }
    Ok(())
}
