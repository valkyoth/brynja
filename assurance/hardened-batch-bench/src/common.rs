use std::hint::black_box;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const SAMPLES: usize = 7;

pub fn check<T, E: core::fmt::Debug>(result: std::result::Result<T, E>) -> Result<T> {
    result.map_err(|error| format!("{error:?}").into())
}

pub fn messages<const N: usize>(bytes: usize, ragged: bool) -> [Vec<u8>; N] {
    core::array::from_fn(|lane| {
        let length = if ragged {
            bytes.saturating_sub(lane)
        } else {
            bytes
        };
        (0..length)
            .map(|i| i.wrapping_add(lane * 17).to_le_bytes()[0])
            .collect()
    })
}

pub fn destinations<const N: usize>(
    bytes: &mut [Vec<u8>; N],
    lanes: usize,
    size: usize,
) -> [Option<&mut [u8]>; N] {
    let mut index = 0;
    bytes.each_mut().map(|slot| {
        let active = index < lanes;
        index += 1;
        active.then_some(&mut slot[..size])
    })
}

pub fn cleanup<const N: usize>(bytes: &[Vec<u8>; N], lanes: usize, size: usize) -> Result<()> {
    for (lane, slot) in bytes.iter().enumerate() {
        if slot[..size]
            .iter()
            .any(|byte| *byte != if lane < lanes { 0 } else { 0xa5 })
            || slot[size] != 0xa5
        {
            return Err("secret Drop/inactive/canary cleanup".into());
        }
    }
    Ok(())
}

pub fn observe(actual: Option<&[u8]>, expected: Option<&[u8]>) -> Result<()> {
    if black_box(actual) != expected {
        return Err("timed digest output mismatch".into());
    }
    Ok(())
}

pub fn measure(
    mut operation: impl FnMut(bool) -> Result<(u128, u64)>,
) -> Result<(u128, u128, u64)> {
    let mut baseline = [0; SAMPLES];
    let mut selected = [0; SAMPLES];
    let (_, expected_calls) = operation(true)?; // Warm both routes outside samples.
    let (_, portable_calls) = operation(false)?;
    if portable_calls != 0 {
        return Err("portable warmup used vectors".into());
    }
    let mut calls = 0_u64;
    for sample in 0..SAMPLES {
        let (a, b) = if sample % 2 == 0 {
            (operation(false)?, operation(true)?)
        } else {
            let b = operation(true)?;
            (operation(false)?, b)
        };
        if a.0 == 0 || b.0 == 0 || a.1 != 0 || b.1 != expected_calls {
            return Err("unstable route or empty timing".into());
        }
        baseline[sample] = a.0;
        selected[sample] = b.0;
        calls = calls
            .checked_add(b.1)
            .ok_or("benchmark vector counter overflow")?;
    }
    baseline.sort_unstable();
    selected.sort_unstable();
    Ok((baseline[SAMPLES / 2], selected[SAMPLES / 2], calls))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timing_and_route_checks_are_load_bearing() {
        assert!(measure(|selected| Ok((1, u64::from(selected)))).is_ok());
        assert!(measure(|_| Ok((0, 0))).is_err());
        assert!(measure(|_| Ok((1, 1))).is_err());
        assert!(measure(|selected| Ok((1, if selected { u64::MAX } else { 0 }))).is_err());
        let mut n = 0;
        assert!(
            measure(|selected| {
                n += 1;
                Ok((1, if selected { n } else { 0 }))
            })
            .is_err()
        );
        assert!(measure(|_| Err("operation failed".into())).is_err());
        assert!(observe(Some(&[1]), Some(&[2])).is_err());
        assert!(cleanup(&[vec![0, 0xa5], vec![0xa5, 0xa5]], 1, 1).is_ok());
        assert!(cleanup(&[vec![1, 0xa5]], 1, 1).is_err());
        assert!(cleanup(&[vec![0, 0]], 1, 1).is_err());
        assert!(cleanup(&[vec![0, 0xa5]], 0, 1).is_err());
    }

    #[test]
    fn median_excludes_warmups_and_alternates_routes() {
        let mut n = 0_u128;
        let mut order = Vec::new();
        let measured = measure(|selected| {
            n += 1;
            order.push(selected);
            Ok((n, u64::from(selected)))
        });
        assert_eq!(measured.ok(), Some((10, 9, 7)));
        assert_eq!(
            order,
            [
                true, false, false, true, true, false, false, true, true, false, false, true, true,
                false, false, true
            ]
        );
    }
}
