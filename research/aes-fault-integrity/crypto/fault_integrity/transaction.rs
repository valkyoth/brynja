//! Private functional lifecycle/rollback prototype, NOT a protected AES owner.
//! Public fixtures only. The callback stands in for computation AND all pre/post
//! schedule checks; this module does not establish those checks or opaque capture.
//! Ordinary equality, the completion codeword and unqualified readback call sites below
//! are deliberately NOT claimed as C1/DC1 or machine-code-qualified authorization.
use super::{Error, ProfileFailure, Scratch};
use crate::aes::{PublicCiphertext, SecretBlock};
use brynja_core::SecretRegionInitialization;
use core::marker::PhantomData;

// Candidate lifecycle codewords, not release tokens. Pairwise bit distances
// are 64, 64, 128; every pair differs in all sixteen bytes. Zero is invalid.
// A whole-codeword overwrite, skipped branch/store or faulty predicate is NOT
// covered merely by using these arrays. Linked-code qualification is pending.
const HEALTHY: [u8; 16] = [0xa5; 16];
const IN_PROGRESS: [u8; 16] = [0x3c; 16];
const TERMINAL: [u8; 16] = [0xc3; 16];
const COMPUTED: [u8; 16] = [0x69; 16];

// A returned Result is not evidence that both computations ran: a fault can
// change an early Err into Ok while both initially empty result blocks agree.
// The computation itself must mark this independent operation-local record.
pub(super) struct Completion {
    word: [u8; 16],
}

impl Completion {
    pub(super) fn new() -> Self {
        Self { word: [0; 16] }
    }

    pub(super) fn mark_complete(&mut self) {
        self.word = COMPUTED;
    }

    pub(super) fn check(&self) -> Result<(), Error> {
        check_state(&self.word, &COMPUTED)
    }
}

fn check_state(word: &[u8; 16], expected: &[u8; 16]) -> Result<(), Error> {
    #[cfg(brynja_fault_primitives)]
    {
        // A direct Rust comparison can be eliminated after the compiler proves
        // there are no ordinary writes to the state. Require a fresh opaque
        // read; this preserves the observation, NOT a fault-protected predicate.
        let mut observed = Scratch::<16>::new();
        brynja_core::copy_secret_region(&mut observed.0, word)?;
        if observed.0 != *expected {
            return Err(Error::SecretMemory);
        }
    }
    #[cfg(not(brynja_fault_primitives))]
    if word != expected {
        return Err(Error::SecretMemory);
    }
    Ok(())
}

pub(super) struct Lifecycle {
    word: [u8; 16],
}

impl Lifecycle {
    pub(super) fn new() -> Self {
        Self { word: HEALTHY }
    }

    fn begin(&mut self) -> Result<Operation<'_>, ProfileFailure> {
        if check_state(&self.word, &HEALTHY).is_err() {
            let already_retired = self.word == TERMINAL;
            self.word = TERMINAL;
            return Err(if already_retired {
                ProfileFailure::AlreadyRetired
            } else {
                ProfileFailure::RejectedAndRetired
            });
        }
        self.word = IN_PROGRESS;
        Ok(Operation {
            owner: self,
            completed: false,
        })
    }

    // No public-decryption entry point exists. This stub consumes the same
    // explicit public-release acknowledgement as ordinary AES, but is test-only.
    pub(super) fn public(
        &mut self,
        output: &mut [u8; 16],
        acknowledgement: PublicCiphertext,
        compute: impl FnOnce(&mut [u8; 16], &mut [u8; 16], &mut Completion) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.public_profile(output, acknowledgement, compute)
            .map_err(Into::into)
    }

    pub(super) fn public_profile(
        &mut self,
        output: &mut [u8; 16],
        _acknowledgement: PublicCiphertext,
        compute: impl FnOnce(&mut [u8; 16], &mut [u8; 16], &mut Completion) -> Result<(), Error>,
    ) -> Result<(), ProfileFailure> {
        let mut destination = PublicTransaction::new(output);
        let operation = self.begin()?;
        let mut primary = Scratch::<16>::new();
        let mut secondary = Scratch::<16>::new();
        let mut completion = Completion::new();
        compute(&mut primary.0, &mut secondary.0, &mut completion)
            .map_err(|_| ProfileFailure::RejectedAndRetired)?;
        completion
            .check()
            .map_err(|_| ProfileFailure::RejectedAndRetired)?;
        #[cfg(brynja_fault_primitives)]
        destination
            .write_guarded(&mut primary.0, &mut secondary.0, &mut operation.owner.word)
            .map_err(|_| ProfileFailure::RejectedAndRetired)?;
        #[cfg(not(brynja_fault_primitives))]
        {
            validate(&primary.0, &primary.0, &secondary.0)
                .map_err(|_| ProfileFailure::RejectedAndRetired)?;
            destination.write(&primary.0);
            validate(destination.output, &primary.0, &secondary.0)
                .map_err(|_| ProfileFailure::RejectedAndRetired)?;
        }
        #[cfg(brynja_fault_primitives)]
        {
            check_state(&operation.owner.word, &IN_PROGRESS)
                .map_err(|_| ProfileFailure::RejectedAndRetired)?;
            super::authorization_model::permit_fresh(
                destination.output,
                &primary.0,
                &secondary.0,
                &mut operation.owner.word,
                &TERMINAL,
                &IN_PROGRESS,
            )
            .map_err(|_| ProfileFailure::RejectedAndRetired)?;
        }
        operation
            .complete()
            .map_err(|_| ProfileFailure::RejectedAndRetired)?;
        destination.commit();
        Ok(())
    }

    pub(super) fn secret<'out>(
        &mut self,
        output: &'out mut [u8; 16],
        compute: impl FnOnce(&mut [u8; 16], &mut [u8; 16], &mut Completion) -> Result<(), Error>,
    ) -> Result<SecretBlock<'out>, Error> {
        self.secret_profile(output, compute).map_err(Into::into)
    }

    pub(super) fn secret_profile<'out>(
        &mut self,
        output: &'out mut [u8; 16],
        compute: impl FnOnce(&mut [u8; 16], &mut [u8; 16], &mut Completion) -> Result<(), Error>,
    ) -> Result<SecretBlock<'out>, ProfileFailure> {
        // Admission precedes even terminal rejection, so every admitted secret
        // destination clears on error. A finished region stays PRIVATE until
        // validation; no new core API or exposure of unverified bytes is needed.
        let mut destination = SecretRegionInitialization::begin(output)
            .map_err(|_| ProfileFailure::DestinationAdmission)?;
        let operation = self.begin()?;
        let mut primary = Scratch::<16>::new();
        let mut secondary = Scratch::<16>::new();
        let mut completion = Completion::new();
        compute(&mut primary.0, &mut secondary.0, &mut completion)
            .map_err(|_| ProfileFailure::RejectedAndRetired)?;
        completion
            .check()
            .map_err(|_| ProfileFailure::RejectedAndRetired)?;
        #[cfg(brynja_fault_primitives)]
        {
            // Existing initialization owners expose no mutable destination.
            // Guard a private clearing staging block, then use the ordinary
            // initialization write and recheck the ACTUAL destination below.
            // The final copy is not an opaque guarded commit on this path.
            let mut staged = Scratch::<16>::new();
            guarded_write(
                &mut staged.0,
                &mut primary.0,
                &mut secondary.0,
                &mut operation.owner.word,
            )
            .map_err(|_| ProfileFailure::RejectedAndRetired)?;
            #[cfg(all(test, brynja_fault_evidence))]
            guarded_tests::checkpoint(
                guarded_tests::Stage::BeforeSecretWrite,
                &mut staged.0,
                &mut primary.0,
                &mut secondary.0,
                &mut operation.owner.word,
            )
            .map_err(|_| ProfileFailure::RejectedAndRetired)?;
            destination
                .write(&staged.0)
                .map_err(|_| ProfileFailure::RejectedAndRetired)?;
        }
        #[cfg(not(brynja_fault_primitives))]
        {
            validate(&primary.0, &primary.0, &secondary.0)
                .map_err(|_| ProfileFailure::RejectedAndRetired)?;
            destination
                .write(&primary.0)
                .map_err(|_| ProfileFailure::RejectedAndRetired)?;
        }
        let region = destination
            .finish()
            .map_err(|_| ProfileFailure::RejectedAndRetired)?;
        validate(region.expose(), &primary.0, &secondary.0)
            .map_err(|_| ProfileFailure::RejectedAndRetired)?;
        #[cfg(brynja_fault_primitives)]
        {
            check_state(&operation.owner.word, &IN_PROGRESS)
                .map_err(|_| ProfileFailure::RejectedAndRetired)?;
            super::authorization_model::permit_fresh(
                region.expose(),
                &primary.0,
                &secondary.0,
                &mut operation.owner.word,
                &TERMINAL,
                &IN_PROGRESS,
            )
            .map_err(|_| ProfileFailure::RejectedAndRetired)?;
        }
        operation
            .complete()
            .map_err(|_| ProfileFailure::RejectedAndRetired)?;
        Ok(SecretBlock {
            region,
            local: PhantomData,
        })
    }
}

struct Operation<'a> {
    owner: &'a mut Lifecycle,
    completed: bool,
}

impl Operation<'_> {
    fn complete(mut self) -> Result<(), Error> {
        #[cfg(all(test, brynja_fault_primitives, brynja_fault_evidence))]
        guarded_tests::before_complete(&mut self.owner.word)?;
        check_state(&self.owner.word, &IN_PROGRESS)?;
        self.owner.word = HEALTHY;
        self.completed = true;
        Ok(())
    }
}

// Public destination OR private secret staging block, always within an active
// rollback/clearing transaction. No receipt survives this helper. Tests exercise
// source mutations plus finite native public-fixture events; lifecycle and
// return branches remain unqualified for the complete fault model.
#[cfg(brynja_fault_primitives)]
fn guarded_write(
    output: &mut [u8; 16],
    primary: &mut [u8; 16],
    secondary: &mut [u8; 16],
    state: &mut [u8; 16],
) -> Result<(), Error> {
    #[cfg(all(test, brynja_fault_evidence))]
    guarded_tests::checkpoint(
        guarded_tests::Stage::BeforeCopy,
        output,
        primary,
        secondary,
        state,
    )?;
    check_state(state, &IN_PROGRESS)?;
    super::authorization_model::copy_fresh(output, primary, secondary)?;
    #[cfg(all(test, brynja_fault_evidence))]
    guarded_tests::checkpoint(
        guarded_tests::Stage::AfterCopy,
        output,
        primary,
        secondary,
        state,
    )?;
    let first = check(output, primary, secondary, false);
    #[cfg(all(test, brynja_fault_evidence))]
    guarded_tests::checkpoint(
        guarded_tests::Stage::BetweenReadbacks,
        output,
        primary,
        secondary,
        state,
    )?;
    let second = check(output, primary, secondary, true);
    first.and(second)?;
    check_state(state, &IN_PROGRESS)?;
    Ok(())
}

impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.word = TERMINAL;
        }
    }
}

struct PublicTransaction<'out> {
    output: &'out mut [u8; 16],
    old: Scratch<16>,
    committed: bool,
}

impl<'out> PublicTransaction<'out> {
    #[cfg(brynja_fault_primitives)]
    fn write_guarded(
        &mut self,
        primary: &mut [u8; 16],
        secondary: &mut [u8; 16],
        state: &mut [u8; 16],
    ) -> Result<(), Error> {
        guarded_write(self.output, primary, secondary, state)
    }

    fn new(output: &'out mut [u8; 16]) -> Self {
        let mut old = Scratch::new();
        old.0.copy_from_slice(output);
        Self {
            output,
            old,
            committed: false,
        }
    }

    fn write(&mut self, proposed: &[u8; 16]) {
        self.output.copy_from_slice(proposed);
    }

    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for PublicTransaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.output.copy_from_slice(&self.old.0);
        }
        // old clears via Scratch on success AND rollback. Old caller bytes
        // may themselves be secret; do not leave a plain backup array behind.
    }
}

// Functional reference only: two full comparisons, each against BOTH replicas.
// No folding checksum; equal nonzero XOR differences cannot cancel under OR.
// Each invocation freshly copies actual destination bytes through core's transfer
// boundary. Reverse/complement structure is not qualification of the comparisons.
fn check(
    destination: &[u8],
    primary: &[u8; 16],
    secondary: &[u8; 16],
    reverse: bool,
) -> Result<(), Error> {
    if destination.len() != 16 {
        return Err(Error::SecretMemory);
    }
    let mut observed = Scratch::<16>::new();
    brynja_core::copy_secret_region(&mut observed.0, destination)?;
    let mut differences = Scratch::<2>::new();
    #[cfg(brynja_fault_primitives)]
    {
        if reverse {
            brynja_core::fault_comparison_workbench::reverse_16(
                &mut differences.0,
                &observed.0,
                primary,
                secondary,
            );
        } else {
            brynja_core::fault_comparison_workbench::forward_16(
                &mut differences.0,
                &observed.0,
                primary,
                secondary,
            );
        }
        // Raw two-byte results are NOT a wide release token. This ordinary
        // decision remains a prototype until encoded authorization is reviewed.
        let expected = if reverse { [0xff; 2] } else { [0; 2] };
        if differences.0 == expected {
            Ok(())
        } else {
            Err(Error::SecretMemory)
        }
    }
    #[cfg(not(brynja_fault_primitives))]
    {
        let [a, b] = &mut differences.0;
        for step in 0usize..16 {
            let position = if reverse {
                15usize.wrapping_sub(step)
            } else {
                step
            };
            let actual = super::read(&observed.0, position)?;
            let p = super::read(primary, position)?;
            let s = super::read(secondary, position)?;
            if reverse {
                *a |= (!actual) ^ (!p);
                *b |= (!actual) ^ (!s);
            } else {
                *a |= actual ^ p;
                *b |= actual ^ s;
            }
        }
        if *a == 0 && *b == 0 {
            Ok(())
        } else {
            Err(Error::SecretMemory)
        }
    }
}

fn validate(destination: &[u8], primary: &[u8; 16], secondary: &[u8; 16]) -> Result<(), Error> {
    // Evaluate both even if the first reports mismatch. This is not a claim
    // of constant failure-stage timing across the enclosing operation.
    let first = check(destination, primary, secondary, false);
    let second = check(destination, primary, secondary, true);
    first.and(second)
}

#[cfg(all(test, brynja_fault_evidence))]
mod evidence_tests;
#[cfg(all(test, brynja_fault_primitives, brynja_fault_evidence))]
mod guarded_tests;
#[cfg(test)]
mod tests;
// Public-data executable fixture, with NO source mutation hooks required.
#[cfg(all(test, brynja_fault_primitives))]
mod probe_tests;
