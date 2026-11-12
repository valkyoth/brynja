// Diagnostic lower bounds, not a correction to subtract from AES samples.
#[repr(C, align(64))]
#[derive(Default)]
struct OverheadCommon {
    key: [u8; 32],
    block: [u8; 16],
}

fn overhead_trial(copy: bool, common: &mut OverheadCommon) -> Result<u128> {
    if copy {
        isolated_timer::<true>(|| {
            let source = black_box(&*common);
            let key = black_box(source.key);
            let block = black_box(source.block);
            black_box((key, block));
            Ok(())
        })
    } else {
        isolated_timer::<true>(|| {
            black_box(());
            Ok(())
        })
    }
}

fn overhead() -> Result<()> {
    println!("AES_TIMING_OVERHEAD {SAMPLES} {REPEAT} {WARMUP} {SEED}");
    let mut common = OverheadCommon::default();
    for (campaign, name, copy) in [(0, "timer", false), (1, "copy", true)] {
        let cases = corpus(campaign);
        let mut records = Vec::with_capacity(SAMPLES);
        for (index, case) in cases.iter().enumerate() {
            let mut elapsed = [0; 2];
            for class in [case.first, 1 - case.first] {
                // Both classes have identical zero values and addresses.
                elapsed[class] = overhead_trial(copy, &mut common)?;
            }
            if index >= WARMUP {
                records.push((case.first, elapsed));
            }
        }
        for (sample, (first, elapsed)) in records.iter().enumerate() {
            println!(
                "OVERHEAD {name} {sample} {first} {} {}",
                elapsed[0], elapsed[1]
            );
        }
    }
    println!("AES_TIMING_OVERHEAD_END");
    Ok(())
}

#[cfg(test)]
mod isolated_tests {
    use super::*;

    #[test]
    fn timer_repetition_and_error_short_circuit_are_exact() {
        let mut calls = 0;
        isolated_timer::<false>(|| {
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 1);
        calls = 0;
        isolated_timer::<true>(|| {
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, REPEAT);
        calls = 0;
        assert!(
            isolated_timer::<true>(|| {
                calls += 1;
                Err("injected".into())
            })
            .is_err()
        );
        assert_eq!(calls, 1);
    }

    #[test]
    fn overhead_never_mutates_input() {
        let mut common = OverheadCommon::default();
        for copy in [false, true] {
            overhead_trial(copy, &mut common).unwrap();
            assert_eq!(common.key, [0; 32]);
            assert_eq!(common.block, [0; 16]);
        }
    }
}
