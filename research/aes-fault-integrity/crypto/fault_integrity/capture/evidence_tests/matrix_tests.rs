//! Enumerated source boundaries only; no emitted-site or D3 qualification.
use super::*;

#[test]
fn mutation_population_and_stuck_bit_cases_are_explicit() -> Result<(), Error> {
    let mut families = [0usize; 4];
    for mutation in mutations() {
        let family = match mutation {
            Mutation::Xor(_) => 0,
            Mutation::Replace(_) => 1,
            Mutation::And(_) => 2,
            Mutation::Or(_) => 3,
        };
        let count = families.get_mut(family).ok_or(Error::SecretMemory)?;
        *count = count.wrapping_add(1);
    }
    assert_eq!(families, [255, 256, 256, 256]);
    for original in 0u8..=255 {
        let mut xor_effective = 0usize;
        for mask in 1u8..=255 {
            if Mutation::Xor(mask).apply(original) != original {
                xor_effective = xor_effective.wrapping_add(1);
            }
        }
        assert_eq!(xor_effective, 255);
        assert_eq!(Mutation::Replace(original).apply(original), original);
        assert_eq!(Mutation::And(255).apply(original), original);
        assert_eq!(Mutation::Or(0).apply(original), original);
        for bit in 0..8 {
            let flag = 1u8 << bit;
            let cleared = Mutation::And(!flag).apply(original);
            let set = Mutation::Or(flag).apply(original);
            assert_eq!(cleared & flag, 0);
            assert_eq!(set & flag, flag);
            assert_eq!(cleared & !flag, original & !flag);
            assert_eq!(set & !flag, original & !flag);
            assert_eq!(cleared == original, original & flag == 0);
            assert_eq!(set == original, original & flag != 0);
        }
    }
    Ok(())
}

#[test]
fn both_capture_boundaries_all_bytes_and_mutations() -> Result<(), Error> {
    let mut effective = 0usize;
    let mut ineffective = 0usize;
    for width in [16usize, 24, 32] {
        for stage in [Stage::AfterFirst, Stage::AfterSecond] {
            for position in 0..width {
                for mutation in mutations() {
                    let input = [0x42; 32];
                    let mut first = [0x91; 34];
                    let mut second = [0x92; 34];
                    let end = width.wrapping_add(1);
                    let reset = inject_at(stage, Action::Mutate(position, mutation));
                    pair(
                        input.get(..width).ok_or(Error::SecretMemory)?,
                        first.get_mut(1..end).ok_or(Error::SecretMemory)?,
                        second.get_mut(1..end).ok_or(Error::SecretMemory)?,
                    )?;
                    assert_eq!(hits(), 1);
                    drop(reset);
                    let mut expected = input;
                    *expected.get_mut(position).ok_or(Error::SecretMemory)? = mutation.apply(0x42);
                    let (a, b) = if stage == Stage::AfterFirst {
                        (&expected, &input)
                    } else {
                        (&input, &expected)
                    };
                    assert_eq!(first.get(1..end), a.get(..width));
                    assert_eq!(second.get(1..end), b.get(..width));
                    assert_eq!(first.first(), Some(&0x91));
                    assert_eq!(second.first(), Some(&0x92));
                    assert!(
                        first
                            .get(end..)
                            .ok_or(Error::SecretMemory)?
                            .iter()
                            .all(|v| *v == 0x91)
                    );
                    assert!(
                        second
                            .get(end..)
                            .ok_or(Error::SecretMemory)?
                            .iter()
                            .all(|v| *v == 0x92)
                    );
                    assert_eq!(input, [0x42; 32]);
                    if expected == input {
                        ineffective = ineffective.wrapping_add(1);
                    } else {
                        effective = effective.wrapping_add(1);
                    }
                }
            }
        }
    }
    // 144 positions/stages * (255 XOR + 256 replacement + 256 AND + 256 OR).
    // For 0x42: 1 replacement + 64 AND + 4 OR masks leave the byte unchanged.
    assert_eq!((effective, ineffective), (137_376, 9_936));
    Ok(())
}

#[test]
fn second_capture_error_unwind_and_invalid_position_are_observed() {
    for action in [
        Action::Error,
        Action::Unwind,
        Action::Mutate(16, Mutation::Xor(1)),
    ] {
        let reset = inject_at(Stage::AfterSecond, action);
        let outcome = catch_unwind(AssertUnwindSafe(|| -> Result<(), Error> {
            let mut first = super::super::super::Scratch::<16>::new();
            let mut second = super::super::super::Scratch::<16>::new();
            pair(&[0x42; 16], &mut first.0, &mut second.0)
        }));
        assert_eq!(hits(), 1);
        drop(reset);
        if matches!(action, Action::Unwind) {
            assert!(outcome.is_err());
        } else {
            assert_eq!(outcome.ok(), Some(Err(Error::SecretMemory)));
        }
        assert!(ACTION.get().is_none());
    }
}
