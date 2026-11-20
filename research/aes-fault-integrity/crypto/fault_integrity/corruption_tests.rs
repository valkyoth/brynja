//! Source-level data corruption of public fixtures only. NOT a fault owner,
//! quarantine implementation, release check, binary simulation or qualification.
//! The ordinary engine methods run unchanged; injection writes test storage.
//! Requires both cfg(test) and explicit --cfg brynja_fault_evidence.
extern crate std;
use super::{Error, primary::Primary, schedule::Schedule};
use std::cell::Cell;
use std::println;

#[derive(Clone, Copy, Eq, PartialEq)]
enum FaultPhase {
    Expansion,
    Transform,
}

#[derive(Clone, Copy)]
struct CoefficientFaultState {
    phase: FaultPhase,
    monomial: usize,
    mask: u8,
    calls: usize,
    effective: usize,
}

std::thread_local! {
    static COEFFICIENT_FAULT: Cell<Option<CoefficientFaultState>> = const { Cell::new(None) };
    static SUBSTITUTION_PHASE: Cell<Option<FaultPhase>> = const { Cell::new(None) };
}

pub(super) struct SubstitutionPhase;

impl SubstitutionPhase {
    fn enter(phase: FaultPhase) -> Self {
        SUBSTITUTION_PHASE.with(|cell| {
            assert!(cell.get().is_none(), "nested substitution fixture");
            cell.set(Some(phase));
        });
        Self
    }

    pub(super) fn expansion() -> Self {
        Self::enter(FaultPhase::Expansion)
    }

    pub(super) fn transform() -> Self {
        Self::enter(FaultPhase::Transform)
    }
}

impl Drop for SubstitutionPhase {
    fn drop(&mut self) {
        SUBSTITUTION_PHASE.with(|cell| cell.set(None));
    }
}

pub(super) struct PersistentCoefficientFault;

impl PersistentCoefficientFault {
    fn install(phase: FaultPhase, monomial: usize, mask: u8) -> Self {
        COEFFICIENT_FAULT.with(|cell| {
            assert!(cell.get().is_none(), "nested fault fixture");
            cell.set(Some(CoefficientFaultState {
                phase,
                monomial,
                mask,
                calls: 0,
                effective: 0,
            }));
        });
        Self
    }

    pub(super) fn install_transform_high() -> Self {
        Self::install(FaultPhase::Transform, 255, 1)
    }

    pub(super) fn install_transform_affine() -> Self {
        Self::install(FaultPhase::Transform, 0, 1)
    }

    pub(super) fn install_expansion_affine() -> Self {
        Self::install(FaultPhase::Expansion, 0, 1)
    }

    pub(super) fn take_counts(&self) -> (usize, usize) {
        COEFFICIENT_FAULT.with(|cell| {
            let Some(state) = cell.get() else {
                return (0, 0);
            };
            cell.set(Some(CoefficientFaultState {
                calls: 0,
                effective: 0,
                ..state
            }));
            (state.calls, state.effective)
        })
    }
}

impl Drop for PersistentCoefficientFault {
    fn drop(&mut self) {
        COEFFICIENT_FAULT.with(|cell| cell.set(None));
    }
}

// Test-only secondary ANF coefficient fault: monomial zero represents an
// always-effective affine constant; monomial 255 is data-dependent.
pub(super) fn coefficient_fault(monomial: usize, coefficient: u8, product: u8) -> u8 {
    COEFFICIENT_FAULT.with(|cell| {
        let Some(mut state) = cell.get() else {
            return coefficient;
        };
        if SUBSTITUTION_PHASE.with(Cell::get) != Some(state.phase) || monomial != state.monomial {
            return coefficient;
        }
        state.calls = state.calls.saturating_add(1);
        if product != 0 {
            state.effective = state.effective.saturating_add(1);
        }
        cell.set(Some(state));
        coefficient ^ state.mask
    })
}

#[derive(Clone, Copy, Debug)]
enum Domain {
    Primary,
    Secondary,
}

#[derive(Clone, Copy)]
enum Mutation {
    Replace(u8),
    Xor(u8),
    And(u8),
    Or(u8),
}

impl Mutation {
    fn apply(self, original: u8) -> u8 {
        match self {
            Self::Replace(value) => value,
            Self::Xor(mask) => original ^ mask,
            Self::And(mask) => original & mask,
            Self::Or(mask) => original | mask,
        }
    }
}

struct Pair {
    primary: Primary,
    secondary: Schedule,
    bytes: usize,
}

impl Pair {
    fn new(width: usize) -> Result<Self, Error> {
        let primary = Primary::new(width)?;
        let bytes = primary.as_bytes().len();
        Ok(Self {
            primary,
            secondary: Schedule::new(),
            bytes,
        })
    }

    fn expand(&mut self, key: &[u8]) -> Result<(), Error> {
        self.primary.expand(key)?;
        self.secondary.expand(key)
    }

    fn slot(&mut self, domain: Domain, position: usize) -> Result<&mut u8, Error> {
        if position >= self.bytes {
            return Err(Error::SecretMemory);
        }
        match domain {
            Domain::Primary => self
                .primary
                .bytes()
                .get_mut(position)
                .ok_or(Error::SecretMemory),
            // One PHYSICAL representation byte: a bit plane spanning eight
            // logical round-key bytes. Not a falsely labeled logical-byte fault.
            Domain::Secondary => self
                .secondary
                .keys
                .get_mut(position / 16)
                .and_then(|p| p.0.0.get_mut(position % 16))
                .ok_or(Error::SecretMemory),
        }
    }

    fn inject(&mut self, domain: Domain, position: usize, mutation: Mutation) -> Result<u8, Error> {
        let slot = self.slot(domain, position)?;
        let original = *slot;
        *slot = mutation.apply(original);
        Ok(original)
    }

    fn run(&self, input: &[u8; 16], inverse: bool) -> Result<([u8; 16], [u8; 16]), Error> {
        // These are public-fixture observations, NOT guarded application output.
        let mut primary = *input;
        self.primary.transform(&mut primary, inverse)?;
        let mut secondary = [0; 16];
        self.secondary.transform(input, &mut secondary, inverse)?;
        Ok((primary, secondary))
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Outcome {
    Mismatch,
    CorrectAgreement,
    WrongAgreement,
}

fn classify(observed: ([u8; 16], [u8; 16]), correct: &[u8; 16]) -> Outcome {
    // Reference oracle only: ordinary equality is NOT a protected release check.
    if observed.0 != observed.1 {
        Outcome::Mismatch
    } else if &observed.0 == correct {
        Outcome::CorrectAgreement
    } else {
        Outcome::WrongAgreement
    }
}

const PLAINTEXT: [u8; 16] = [
    0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
// FIPS 197 example vectors with keys 00,01,... (not an agreement-only oracle).
const CASES: [(usize, [u8; 16]); 3] = [
    (
        16,
        [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ],
    ),
    (
        24,
        [
            0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d,
            0x71, 0x91,
        ],
    ),
    (
        32,
        [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ],
    ),
];

fn key() -> Result<[u8; 32], Error> {
    let mut key = [0; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::try_from(i).map_err(|_| Error::SecretMemory)?;
    }
    Ok(key)
}

#[test]
fn mutation_families_and_invalid_sites_are_explicit() -> Result<(), Error> {
    for value in 0..=u8::MAX {
        assert_eq!(Mutation::Replace(value).apply(value), value);
        assert_eq!(Mutation::Xor(0).apply(value), value);
        assert_ne!(Mutation::Xor(1).apply(value), value);
        assert_eq!(Mutation::And(0xfe).apply(value), value & 0xfe);
        assert_eq!(Mutation::Or(1).apply(value), value | 1);
    }
    assert!(Pair::new(17).is_err());
    let mut pair = Pair::new(16)?;
    pair.expand(key()?.get(..16).ok_or(Error::SecretMemory)?)?;
    for domain in [Domain::Primary, Domain::Secondary] {
        for position in [176, 240, usize::MAX] {
            assert!(pair.inject(domain, position, Mutation::Xor(1)).is_err());
        }
    }
    assert_eq!(
        classify(
            pair.run(&PLAINTEXT, false)?,
            &CASES.first().ok_or(Error::SecretMemory)?.1
        ),
        Outcome::CorrectAgreement
    );
    Ok(())
}

#[test]
fn persistent_schedule_changes_survive_repeated_calls_without_repair() -> Result<(), Error> {
    let raw = key()?;
    for (width, ciphertext) in CASES {
        for inverse in [false, true] {
            let (input, expected) = if inverse {
                (ciphertext, PLAINTEXT)
            } else {
                (PLAINTEXT, ciphertext)
            };
            for domain in [Domain::Primary, Domain::Secondary] {
                let mut pair = Pair::new(width)?;
                pair.expand(raw.get(..width).ok_or(Error::SecretMemory)?)?;
                for position in [0, pair.bytes / 2, pair.bytes.wrapping_sub(1)] {
                    let original = pair.inject(domain, position, Mutation::Xor(0x5a))?;
                    for _ in 0..2 {
                        assert_eq!(
                            classify(pair.run(&input, inverse)?, &expected),
                            Outcome::Mismatch
                        );
                        assert_eq!(*pair.slot(domain, position)?, original ^ 0x5a);
                    }
                    // Independent experimental trial reset, NOT an application
                    // recovery or a production owner allowed to repair and retry.
                    *pair.slot(domain, position)? = original;
                    assert_eq!(
                        classify(pair.run(&input, inverse)?, &expected),
                        Outcome::CorrectAgreement
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn common_mode_wrong_input_and_wrong_key_are_negative_controls() -> Result<(), Error> {
    let raw = key()?;
    for (width, ciphertext) in CASES {
        for inverse in [false, true] {
            let (input, expected) = if inverse {
                (ciphertext, PLAINTEXT)
            } else {
                (PLAINTEXT, ciphertext)
            };
            let mut pair = Pair::new(width)?;
            pair.expand(raw.get(..width).ok_or(Error::SecretMemory)?)?;
            let mut wrong_input = input;
            *wrong_input.first_mut().ok_or(Error::SecretMemory)? ^= 1;
            assert_eq!(
                classify(pair.run(&wrong_input, inverse)?, &expected),
                Outcome::WrongAgreement
            );
            let mut wrong_key = raw;
            *wrong_key.first_mut().ok_or(Error::SecretMemory)? ^= 1;
            pair.expand(wrong_key.get(..width).ok_or(Error::SecretMemory)?)?;
            assert_eq!(
                classify(pair.run(&input, inverse)?, &expected),
                Outcome::WrongAgreement
            );
        }
    }
    Ok(())
}

#[test]
fn a_single_changed_input_replica_diverges_but_is_not_opaque_capture_evidence() -> Result<(), Error>
{
    let raw = key()?;
    for (width, ciphertext) in CASES {
        let mut pair = Pair::new(width)?;
        pair.expand(raw.get(..width).ok_or(Error::SecretMemory)?)?;
        for inverse in [false, true] {
            let (input, expected) = if inverse {
                (ciphertext, PLAINTEXT)
            } else {
                (PLAINTEXT, ciphertext)
            };
            for lane in 0..16 {
                let mut changed = input;
                *changed.get_mut(lane).ok_or(Error::SecretMemory)? ^= 1;
                let correct_pair = pair.run(&input, inverse)?;
                let changed_pair = pair.run(&changed, inverse)?;
                assert_eq!(
                    classify((changed_pair.0, correct_pair.1), &expected),
                    Outcome::Mismatch
                );
                assert_eq!(
                    classify((correct_pair.0, changed_pair.1), &expected),
                    Outcome::Mismatch
                );
            }
        }
    }
    Ok(())
}

#[test]
#[ignore = "explicit optimized source-data campaign; use --release --ignored --nocapture"]
fn every_retained_schedule_byte_replacement() -> Result<(), Error> {
    // Runtime refusal keeps ordinary debug compilation/linting available while
    // preventing accidental execution of the large campaign without --release.
    if cfg!(debug_assertions) {
        return Err(Error::SecretMemory);
    }
    let raw = key()?;
    let mut populations = [0usize; 3];
    let mut mismatches = 0usize;
    let mut ineffective = 0usize;
    for ((width, ciphertext), population) in CASES.into_iter().zip(&mut populations) {
        for inverse in [false, true] {
            let (input, expected) = if inverse {
                (ciphertext, PLAINTEXT)
            } else {
                (PLAINTEXT, ciphertext)
            };
            for domain in [Domain::Primary, Domain::Secondary] {
                let mut pair = Pair::new(width)?;
                pair.expand(raw.get(..width).ok_or(Error::SecretMemory)?)?;
                assert_eq!(
                    classify(pair.run(&input, inverse)?, &expected),
                    Outcome::CorrectAgreement
                );
                for position in 0..pair.bytes {
                    let original = *pair.slot(domain, position)?;
                    for value in 0..=u8::MAX {
                        pair.inject(domain, position, Mutation::Replace(value))?;
                        assert_eq!(*pair.slot(domain, position)?, value);
                        let outcome = classify(pair.run(&input, inverse)?, &expected);
                        if value == original {
                            assert_eq!(outcome, Outcome::CorrectAgreement);
                            ineffective = ineffective.checked_add(1).ok_or(Error::SecretMemory)?;
                        } else {
                            assert_eq!(
                                outcome,
                                Outcome::Mismatch,
                                "width={width} inverse={inverse} domain={domain:?} offset={position} replacement={value}"
                            );
                            mismatches = mismatches.checked_add(1).ok_or(Error::SecretMemory)?;
                        }
                        *population = population.checked_add(1).ok_or(Error::SecretMemory)?;
                        *pair.slot(domain, position)? = original;
                    }
                }
            }
        }
    }
    assert_eq!(populations, [180224, 212992, 245760]);
    assert_eq!(mismatches, 636480);
    assert_eq!(ineffective, 2496);
    println!(
        "SOURCE_DATA_ONLY: trials=638976 mismatch=636480 ineffective_correct=2496 wrong_agreement=0; one key/block per width/direction; no lifecycle, release or binary qualification"
    );
    Ok(())
}
