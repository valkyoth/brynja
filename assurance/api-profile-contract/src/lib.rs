#![no_std]
#![doc = "Type-system fixture for the v0.24.6 API-profile architecture."]

use brynja_core::{OwnedSecretRegion, SecretMemoryError, SecretRegionInitialization};

mod sealed {
    pub trait Registered {}
}

/// Capability implemented only by a registered hardened owner.
///
/// Downstream crates cannot implement or forge this capability because its
/// required supertrait is private.
///
/// ```compile_fail
/// use brynja_api_profile_contract_fixture::HardenedState;
/// struct Forged;
/// impl HardenedState for Forged {}
/// ```
pub trait HardenedState: sealed::Registered {}

/// An ordinary public-data state that deliberately lacks hardened ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrdinaryState;

/// One registered hardened-state identity used only by this fixture.
///
/// The private field prevents direct construction. Real algorithm crates will
/// own their equivalent sealed type and construction invariants.
pub struct RegisteredHardenedState {
    _private: (),
}

impl sealed::Registered for RegisteredHardenedState {}
impl HardenedState for RegisteredHardenedState {}

/// Requires a sealed hardened-state capability.
///
/// ```compile_fail
/// use brynja_api_profile_contract_fixture::{OrdinaryState, require_hardened};
/// require_hardened(&OrdinaryState);
/// ```
///
/// ```compile_fail
/// use brynja_api_profile_contract_fixture::{
///     HardenedState, RegisteredHardenedState, require_hardened,
/// };
/// struct Wrapper(RegisteredHardenedState);
/// impl HardenedState for Wrapper {}
/// require_hardened(&Wrapper(loop {}));
/// ```
pub fn require_hardened<State: HardenedState>(_state: &State) {}

/// Explicit authority to declassify one cryptographic output as public.
///
/// Construction is an affirmative caller action rather than an implicit
/// property of a raw output buffer.
#[must_use = "public declassification must be consumed by the output operation"]
pub struct PublicDeclassification {
    _private: (),
}

impl PublicDeclassification {
    /// Explicitly acknowledges that the output is intended to become public.
    #[must_use]
    pub const fn acknowledge() -> Self {
        Self { _private: () }
    }
}

/// Copies an explicitly declassified public result transactionally.
pub fn write_public(
    source: &[u8],
    destination: &mut [u8],
    _authority: PublicDeclassification,
) -> Result<(), OutputError> {
    if source.len() != destination.len() {
        return Err(OutputError::LengthMismatch);
    }
    for (output, input) in destination.iter_mut().zip(source.iter()) {
        *output = *input;
    }
    Ok(())
}

/// Writes typed secret output through the mandatory core owner.
///
/// Any error or recoverable unwind drops the initialization value and clears
/// the complete destination. Success transfers clearing duty to the returned
/// affine owner.
pub fn write_secret<'output>(
    source: &[u8],
    destination: &'output mut [u8],
) -> Result<OwnedSecretRegion<'output>, OutputError> {
    let mut initialization = SecretRegionInitialization::begin(destination)?;
    initialization.write(source)?;
    initialization.finish().map_err(OutputError::from)
}

/// Closed output-classification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputError {
    /// Source and destination lengths differ.
    LengthMismatch,
    /// Mandatory secret ownership or clearing failed.
    SecretMemory,
}

impl From<SecretMemoryError> for OutputError {
    fn from(_error: SecretMemoryError) -> Self {
        Self::SecretMemory
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::{OutputError, PublicDeclassification, write_public, write_secret};

    #[test]
    fn public_output_requires_explicit_declassification() {
        let mut output = [0xa5_u8; 3];
        let result = write_public(
            &[1, 2, 3],
            &mut output,
            PublicDeclassification::acknowledge(),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(output, [1, 2, 3]);
    }

    #[test]
    fn public_failure_leaves_destination_unchanged() {
        let mut output = [0xa5_u8; 2];
        let result = write_public(
            &[1, 2, 3],
            &mut output,
            PublicDeclassification::acknowledge(),
        );
        assert_eq!(result, Err(OutputError::LengthMismatch));
        assert_eq!(output, [0xa5; 2]);
    }

    #[test]
    fn secret_success_transfers_affine_clearing_ownership() {
        let mut output = [0xa5_u8; 3];
        {
            let owner = write_secret(&[1, 2, 3], &mut output);
            let Ok(owner) = owner else { return };
            assert_eq!(owner.expose(), &[1, 2, 3]);
        }
        assert_eq!(output, [0; 3]);
    }

    #[test]
    fn secret_failure_clears_complete_destination() {
        let mut output = [0xa5_u8; 2];
        match write_secret(&[1, 2, 3], &mut output) {
            Err(OutputError::SecretMemory) => {}
            Err(OutputError::LengthMismatch) => panic!("wrong closed error"),
            Ok(owner) => {
                drop(owner);
                panic!("oversized secret unexpectedly succeeded");
            }
        }
        assert_eq!(output, [0; 2]);
    }

    #[test]
    fn recoverable_unwind_clears_partial_secret_destination() {
        let mut output = [0xa5_u8; 4];
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut initialization =
                brynja_core::SecretRegionInitialization::begin(&mut output)
                    .unwrap_or_else(|_| panic!("fixture setup failed"));
            initialization
                .write(&[1, 2])
                .unwrap_or_else(|_| panic!("fixture write failed"));
            panic!("injected recoverable unwind");
        }));
        assert!(result.is_err());
        assert_eq!(output, [0; 4]);
    }
}
