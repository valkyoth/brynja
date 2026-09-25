use super::{Cancellation, Error};
use brynja_legacy_sha1::{BitString, hardened_in_place};

// Called only inside the preacquired protected stack. Creates all workspace,
// scratch and digest bytes here, never captures/moves populated state from the
// caller. Only borrowed input/output addresses and public metadata cross join.
pub(super) fn run(
    chunks: &[&[u8]],
    tail: &[u8],
    valid_bits: u8,
    cancel: &Cancellation,
    destination: &mut [u8],
) -> Result<(), Error> {
    checkpoint(cancel)?;
    let tail = BitString::new(tail, valid_bits).map_err(|_| Error::InvalidBits)?;
    let (complete, partial) = tail.split_borrowed();
    let last = match partial {
        Some((byte, bits)) => BitString::new(core::slice::from_ref(byte), bits),
        None => BitString::new(&[], 0),
    }
    .map_err(|_| Error::InvalidBits)?;
    let mut scratch = [0u8; 20];
    let staged = scratch.get_mut(..20).ok_or(Error::Invariant)?;
    #[cfg(test)]
    super::tests::observe_storage(staged);

    macro_rules! compute {
        ($workspace:expr, $borrow:ident) => {{
            let mut workspace = $workspace;
            #[cfg(test)]
            super::tests::observe_storage(&workspace);
            workspace.with(|mut state| {
                for chunk in chunks.iter().copied().chain(core::iter::once(complete)) {
                    checkpoint(cancel)?;
                    for part in chunk.chunks(4096) {
                        checkpoint(cancel)?;
                        state.update(part).map_err(|_| Error::Invariant)?;
                    }
                }
                checkpoint(cancel)?;
                let secret = state
                    .finalize_bits_secret(last, staged)
                    .map_err(|_| Error::Invariant)?;
                checkpoint(cancel)?;
                brynja_core::copy_secret_region(destination, secret.$borrow())
                    .map_err(|_| Error::Invariant)?;
                #[cfg(test)]
                super::tests::after_write();
                // Drop clears staged bytes. workspace.with independently clears
                // the state; join then clears all stack frames/padding/spills.
                Ok(())
            })
        }};
    }
    compute!(hardened_in_place::Sha1Workspace::new(), expose)
}

fn checkpoint(cancel: &Cancellation) -> Result<(), Error> {
    #[cfg(test)]
    super::tests::checkpoint(cancel);
    cancel.check()
}
