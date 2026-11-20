use super::*;

fn receipts() -> ([u8; 32], [u8; 32]) {
    let mut f = [0; 32];
    let mut r = [0; 32];
    for (byte, code) in f.iter_mut().zip([0xa5, 0x3c].into_iter().cycle()) {
        *byte = code;
    }
    for (byte, code) in r.iter_mut().zip([0x5a, 0xc3].into_iter().cycle()) {
        *byte = code;
    }
    (f, r)
}

// Single-call public fixture for debugger experiments. No fault hook is built
// into the leaf. This is still a test artifact, NOT the final AES owner.
#[test]
fn both_bad_receipts_leave_output_unchanged() {
    let (mut f, mut r) = receipts();
    f[0] ^= 1;
    r[0] ^= 1;
    let mut output = [0x91; 16];
    let mut report = 0xff;
    tentative_copy_16(&mut output, &[0x42; 16], &f, &r, &mut report);
    assert_eq!(output, [0x91; 16]);
    assert_eq!(report, 0);
}

#[test]
fn every_receipt_byte_replacement_matches_reference() -> Result<(), &'static str> {
    for path in [false, true] {
        for position in 0..32 {
            for replacement in 0u8..=255 {
                let (mut f, mut r) = receipts();
                let bytes = if path { &mut r } else { &mut f };
                let byte = bytes.get_mut(position).ok_or("receipt index")?;
                let original = *byte;
                *byte = replacement;
                let mut output = [0x91; 16];
                let mut reference = output;
                let mut report = 0xff;
                let mut expected_report = report;
                model(&mut reference, &[0x42; 16], &f, &r, &mut expected_report);
                tentative_copy_16(&mut output, &[0x42; 16], &f, &r, &mut report);
                assert_eq!(output, reference);
                assert_eq!(report, expected_report);
                assert_eq!(report == 0xa5, replacement == original);
            }
        }
    }
    Ok(())
}

#[test]
fn valid_receipts_accept_arbitrary_data_but_zero_or_swapped_receipts_reject() {
    let (f, r) = receipts();
    for byte in 0u8..=255 {
        let mut output = [0x91; 16];
        let mut report = 0;
        tentative_copy_16(&mut output, &[byte; 16], &f, &r, &mut report);
        assert_eq!(output, [byte; 16]); // Not proof that proposed is AES output.
        assert_eq!(report, 0xa5);
        tentative_copy_16(&mut output, &[!byte; 16], &r, &f, &mut report);
        assert_eq!(output, [byte; 16]);
        assert_eq!(report, 0);
        tentative_copy_16(&mut output, &[!byte; 16], &[0; 32], &[0; 32], &mut report);
        assert_eq!(output, [byte; 16]);
        assert_eq!(report, 0);
    }
}

#[test]
fn unaligned_exact_writes_preserve_neighbors_and_inputs() -> Result<(), &'static str> {
    let (f, r) = receipts();
    for offset in 0..16 {
        let mut output = [0x91; 48];
        let mut input = [0x42; 48];
        let mut forward = [0; 64];
        let mut reverse = [0; 64];
        forward
            .get_mut(offset..offset + 32)
            .ok_or("forward slice")?
            .copy_from_slice(&f);
        reverse
            .get_mut(offset..offset + 32)
            .ok_or("reverse slice")?
            .copy_from_slice(&r);
        *input.get_mut(offset).ok_or("input index")? = 0xff;
        let before = input;
        let mut report = [0x22; 3];
        tentative_copy_16(
            output
                .get_mut(offset..offset + 16)
                .ok_or("output slice")?
                .try_into()
                .map_err(|_| "output size")?,
            input
                .get(offset..offset + 16)
                .ok_or("input slice")?
                .try_into()
                .map_err(|_| "input size")?,
            forward
                .get(offset..offset + 32)
                .ok_or("forward slice")?
                .try_into()
                .map_err(|_| "forward size")?,
            reverse
                .get(offset..offset + 32)
                .ok_or("reverse slice")?
                .try_into()
                .map_err(|_| "reverse size")?,
            &mut report[1],
        );
        assert_eq!(
            output.get(offset..offset + 16),
            input.get(offset..offset + 16)
        );
        assert!(
            output
                .get(..offset)
                .ok_or("prefix")?
                .iter()
                .all(|byte| *byte == 0x91)
        );
        assert!(
            output
                .get(offset + 16..)
                .ok_or("suffix")?
                .iter()
                .all(|byte| *byte == 0x91)
        );
        assert_eq!(input, before);
        assert_eq!(report, [0x22, 0xa5, 0x22]);
    }
    Ok(())
}
