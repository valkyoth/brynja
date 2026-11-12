// Test fixture only. Replaces the original width macro in the dispatch-isolation
// experiment; it does not modify a crate API or the historical timing fixture.
fn isolated_timer<const MEASURING: bool>(
    mut operation: impl FnMut() -> Result<()>,
) -> Result<u128> {
    let start = Instant::now();
    for _ in 0..if MEASURING { REPEAT } else { 1 } {
        operation()?;
    }
    Ok(start.elapsed().as_nanos())
}

macro_rules! width {
    ($trial:ident, $key:ident, $cached:ident, $k:literal, $s:literal) => {
        fn $trial(
            authority: &Authority,
            owner: &str,
            mode: &str,
            input_key: &[u8; 32],
            input: &[u8; 16],
            measuring: bool,
        ) -> Result<(u128, String)> {
            fn selected<const MEASURING: bool>(
                authority: &Authority,
                owner: &str,
                mode: &str,
                input_key: &[u8; 32],
                input: &[u8; 16],
            ) -> Result<(u128, String)> {
                if !(MODES.contains(&mode) && matches!(owner, "ephemeral" | "cached")
                    || owner == "cached-import" && mode == "import-key")
                {
                    return Err("unknown timing configuration".into());
                }
                let input_key: &[u8; $k] = input_key[..$k].try_into().map_err(|_| "key width")?;
                let mut storage = [0; $k];
                let mut schedule = [0; $s];
                let mut destination = [0; 16];
                let mut hex = String::new();
                let mut observe = |bytes: &[u8]| {
                    black_box(bytes);
                    if !MEASURING {
                        for byte in bytes {
                            write!(hex, "{byte:02x}").expect("String write");
                        }
                    }
                };
                // Each macro expansion is a separate timer/closure. The string
                // dispatch is before Instant::now, not inside each repetition.
                macro_rules! secret {
                    ($make:expr, $method:ident) => {
                        isolated_timer::<MEASURING>(|| {
                            let key = $make;
                            let block = key
                                .$method(black_box(input), &mut destination)
                                .map_err(|e| format!("{e:?}"))?;
                            observe(block.expose());
                            Ok(())
                        })?
                    };
                }
                macro_rules! public {
                    ($make:expr) => {
                        isolated_timer::<MEASURING>(|| {
                            let key = $make;
                            key.encrypt_block_public(
                                black_box(input),
                                &mut destination,
                                PublicCiphertext::acknowledge(),
                            )
                            .map_err(|e| format!("{e:?}"))?;
                            observe(&destination);
                            Ok(())
                        })?
                    };
                }
                macro_rules! operation {
                    ($make:expr) => {
                        match mode {
                            "encrypt-key" | "encrypt-block" => secret!($make, encrypt_block),
                            "decrypt-key" | "decrypt-block" => secret!($make, decrypt_block),
                            "public-key" | "public-block" => public!($make),
                            _ => return Err("unknown timing mode".into()),
                        }
                    };
                }
                let elapsed = match owner {
                    "ephemeral" => operation!(
                        $key::new(authority, black_box(input_key), black_box(&mut storage))
                            .map_err(|e| format!("{e:?}"))?
                    ),
                    "cached" => {
                        let key = $cached::new(authority, black_box(input_key), &mut schedule)
                            .map_err(|e| format!("{e:?}"))?;
                        operation!(black_box(&key))
                        // Cached schedule Drop remains outside the timer.
                    }
                    "cached-import" => isolated_timer::<MEASURING>(|| {
                        let key =
                            $cached::new(authority, black_box(input_key), black_box(&mut schedule))
                                .map_err(|e| format!("{e:?}"))?;
                        black_box(&key);
                        if !MEASURING {
                            let block = key
                                .encrypt_block(input, &mut destination)
                                .map_err(|e| format!("{e:?}"))?;
                            observe(block.expose());
                        }
                        Ok(())
                    })?,
                    _ => return Err("unknown timing owner".into()),
                };
                Ok((elapsed, hex))
            }
            if measuring {
                selected::<true>(authority, owner, mode, input_key, input)
            } else {
                selected::<false>(authority, owner, mode, input_key, input)
            }
        }
    };
}
