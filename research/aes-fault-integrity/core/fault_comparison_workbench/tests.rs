use super::*;

#[test]
fn every_byte_pair_matches_both_raw_accumulator_encodings() {
    for a in 0..=u8::MAX {
        for b in 0..=u8::MAX {
            let mut forward = [0x91; 2];
            let mut reverse = [0x92; 2];
            forward_16(&mut forward, &[a; 16], &[b; 16], &[a; 16]);
            reverse_16(&mut reverse, &[a; 16], &[b; 16], &[a; 16]);
            assert_eq!(forward, [a ^ b, 0]);
            assert_eq!(reverse, [!(a ^ b), 0xff]);
        }
    }
}

#[test]
fn every_bit_pattern_at_every_position_and_operand_matches_models() -> Result<(), &'static str> {
    for selected in 0..3 {
        for position in 0..16 {
            for mask in 1..=u8::MAX {
                let mut observed = [0x42; 16];
                let mut primary = observed;
                let mut secondary = observed;
                let changed = match selected {
                    0 => &mut observed,
                    1 => &mut primary,
                    _ => &mut secondary,
                };
                *changed.get_mut(position).ok_or("position")? ^= mask;
                let mut actual = [0x91; 2];
                let mut expected = [0x92; 2];
                forward_16(&mut actual, &observed, &primary, &secondary);
                model_forward(&mut expected, &observed, &primary, &secondary);
                assert_eq!(actual, expected);
                assert_ne!(actual, [0; 2]);
                reverse_16(&mut actual, &observed, &primary, &secondary);
                model_reverse(&mut expected, &observed, &primary, &secondary);
                assert_eq!(actual, expected);
                assert_ne!(actual, [0xff; 2]);
            }
        }
    }
    Ok(())
}

#[test]
fn mixed_lanes_aliasing_inputs_and_non_cancellation() {
    for seed in 0..=u8::MAX {
        let mut observed = [0; 16];
        let mut primary = [0; 16];
        let mut secondary = [0; 16];
        for (((o, p), s), i) in observed
            .iter_mut()
            .zip(&mut primary)
            .zip(&mut secondary)
            .zip(0u8..16)
        {
            *o = seed.wrapping_add(i);
            *p = seed.rotate_left(u32::from(i % 8));
            *s = seed.wrapping_sub(i);
        }
        let mut actual = [0; 2];
        let mut expected = [0; 2];
        forward_16(&mut actual, &observed, &primary, &secondary);
        model_forward(&mut expected, &observed, &primary, &secondary);
        assert_eq!(actual, expected);
        reverse_16(&mut actual, &observed, &primary, &secondary);
        model_reverse(&mut expected, &observed, &primary, &secondary);
        assert_eq!(actual, expected);
        forward_16(&mut actual, &observed, &observed, &observed);
        assert_eq!(actual, [0; 2]);
        reverse_16(&mut actual, &observed, &observed, &observed);
        assert_eq!(actual, [0xff; 2]);
    }
    let mut output = [0; 2];
    forward_16(&mut output, &[0; 16], &[1; 16], &[1; 16]);
    assert_eq!(output, [1; 2]);
    reverse_16(&mut output, &[0; 16], &[1; 16], &[1; 16]);
    assert_eq!(output, [0xfe; 2]);
}

#[test]
fn all_unaligned_inputs_preserve_neighbors_and_overwrite_exact_output() -> Result<(), &'static str>
{
    for offset in 0usize..16 {
        let mut input = [0x42; 32];
        let mut p = [0x42; 32];
        let mut s = [0x42; 32];
        *input.get_mut(offset).ok_or("position")? = 0x43;
        *p.get_mut(offset).ok_or("position")? = 0x44;
        *s.get_mut(offset).ok_or("position")? = 0x46;
        let end = offset.checked_add(16).ok_or("end")?;
        let observed: &[u8; 16] = input
            .get(offset..end)
            .ok_or("input")?
            .try_into()
            .map_err(|_| "width")?;
        let primary: &[u8; 16] = p
            .get(offset..end)
            .ok_or("primary")?
            .try_into()
            .map_err(|_| "width")?;
        let secondary: &[u8; 16] = s
            .get(offset..end)
            .ok_or("secondary")?
            .try_into()
            .map_err(|_| "width")?;
        let before = (input, p, s);
        for reverse in [false, true] {
            let mut storage = [0x91, 0x92, 0x93, 0x94];
            let out: &mut [u8; 2] = storage
                .get_mut(1..3)
                .ok_or("output")?
                .try_into()
                .map_err(|_| "width")?;
            if reverse {
                reverse_16(out, observed, primary, secondary);
            } else {
                forward_16(out, observed, primary, secondary);
            }
            assert_eq!(
                storage,
                if reverse {
                    [0x91, !7, !5, 0x94]
                } else {
                    [0x91, 7, 5, 0x94]
                }
            );
            assert_eq!((input, p, s), before);
        }
    }
    Ok(())
}
