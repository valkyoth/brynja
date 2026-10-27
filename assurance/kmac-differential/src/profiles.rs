macro_rules! profile {
    ($module:ident, $api:path, $scoped:path, $with_bits_conformance:ident, $finalize_secret_bits_conformance:ident, $finalize_tag_bits_conformance:ident, $verify_bits_conformance:ident, $finalize_bits_xof_conformance:ident, $new_bits_conformance:ident) => {
        pub(crate) mod $module {
            use super::super::*;
            use api::{Kmac128, Kmac256, KmacXof128, KmacXof256};
            use $api as api;
            use $scoped as scoped;
            // Compare each scoped fixed-output path with the value independently checked by
            // the Python oracle. Initialize destinations incorrectly to reject stale output.
            pub(crate) fn scoped_fixed(
                algorithm: &str,
                key: Fips202BitString<'_>,
                custom: Fips202BitString<'_>,
                message: Fips202BitString<'_>,
                output_bits: usize,
                expected: &[u8],
            ) -> Result<(), Box<dyn Error>> {
                use scoped::{Kmac128Workspace, Kmac256Workspace};
                macro_rules! check {
                    ($workspace:ident) => {{
                        let mut workspace = $workspace::new();
                        let valid = valid_bits(output_bits);
                        let mut actual: Vec<u8> = expected.iter().map(|byte| !byte).collect();
                        let secret = workspace
                            .$with_bits_conformance(key, custom, |state| {
                                state.$finalize_secret_bits_conformance(message, &mut actual, valid)
                            })
                            .and_then(core::convert::identity)
                            .map_err(|_| io::Error::other("scoped secret operation failed"))?;
                        if secret.expose() != expected {
                            return Err(io::Error::other("scoped secret/oracle mismatch").into());
                        }
                        drop(secret);
                        if actual.iter().any(|byte| *byte != 0) {
                            return Err(
                                io::Error::other("scoped secret destination not cleared").into()
                            );
                        }
                        for (byte, expected) in actual.iter_mut().zip(expected) {
                            *byte = !expected;
                        }
                        let tag = workspace
                            .$with_bits_conformance(key, custom, |state| {
                                state.$finalize_tag_bits_conformance(message, &mut actual, valid)
                            })
                            .and_then(core::convert::identity)
                            .map_err(|_| io::Error::other("scoped public operation failed"))?;
                        if tag.as_bytes() != expected {
                            return Err(io::Error::other("scoped public/oracle mismatch").into());
                        }
                        let candidate = Fips202BitString::new(expected, valid)
                            .map_err(|_| io::Error::other("scoped candidate shape"))?;
                        if workspace
                            .$with_bits_conformance(key, custom, |state| {
                                state.$verify_bits_conformance(message, candidate)
                            })
                            .and_then(core::convert::identity)
                            != Ok(())
                        {
                            return Err(
                                io::Error::other("scoped oracle verification rejected").into()
                            );
                        }
                        if !expected.is_empty() {
                            for position in [0, expected.len() - 1] {
                                let mut bad = expected.to_vec();
                                bad[position] ^= 1;
                                let candidate = Fips202BitString::new(&bad, valid)
                                    .map_err(|_| io::Error::other("scoped candidate shape"))?;
                                let verified = workspace
                                    .$with_bits_conformance(key, custom, |state| {
                                        state.$verify_bits_conformance(message, candidate)
                                    })
                                    .and_then(core::convert::identity);
                                if verified != Err(brynja_mac_kmac::KmacError::Mismatch) {
                                    return Err(
                                        io::Error::other("scoped wrong-tag mismatch").into()
                                    );
                                }
                            }
                        }
                    }};
                }
                match algorithm {
                    "kmac128" => check!(Kmac128Workspace),
                    "kmac256" => check!(Kmac256Workspace),
                    _ => (),
                }
                Ok(())
            }

            pub(crate) fn scoped_xof(
                algorithm: &str,
                key: Fips202BitString<'_>,
                custom: Fips202BitString<'_>,
                message: Fips202BitString<'_>,
                output_bits: usize,
                expected: &[u8],
            ) -> Result<(), Box<dyn Error>> {
                use scoped::{KmacXof128Workspace, KmacXof256Workspace};
                macro_rules! check {
                    ($workspace:ident) => {{
                        let mut workspace = $workspace::new();
                        let valid = valid_bits(output_bits);
                        let mut actual: Vec<u8> = expected.iter().map(|byte| !byte).collect();
                        let secret = workspace
                            .$with_bits_conformance(key, custom, |state| {
                                state
                                    .$finalize_bits_xof_conformance(message)?
                                    .squeeze_final_bits_secret(&mut actual, valid)
                            })
                            .and_then(core::convert::identity)
                            .map_err(|_| io::Error::other("scoped XOF secret failure"))?;
                        if secret.expose() != expected {
                            return Err(io::Error::other("scoped XOF oracle mismatch").into());
                        }
                        drop(secret);
                        if actual.iter().any(|byte| *byte != 0) {
                            return Err(
                                io::Error::other("scoped XOF destination not cleared").into()
                            );
                        }
                        for (byte, expected) in actual.iter_mut().zip(expected) {
                            *byte = !expected;
                        }
                        workspace
                            .$with_bits_conformance(key, custom, |state| {
                                let mut reader = state.$finalize_bits_xof_conformance(message)?;
                                let split = actual.len().saturating_sub(1);
                                let (complete, tail) = actual.split_at_mut(split);
                                for chunk in complete.chunks_mut(73) {
                                    reader.squeeze_public(
                                        chunk,
                                        KmacPublicDeclassification::acknowledge(),
                                    )?;
                                }
                                reader.squeeze_final_bits_public(
                                    tail,
                                    valid,
                                    KmacPublicDeclassification::acknowledge(),
                                )
                            })
                            .and_then(core::convert::identity)
                            .map_err(|_| io::Error::other("scoped XOF public failure"))?;
                        if actual != expected {
                            return Err(
                                io::Error::other("scoped XOF incremental oracle mismatch").into()
                            );
                        }
                    }};
                }
                match algorithm {
                    "kmacxof128" => check!(KmacXof128Workspace),
                    "kmacxof256" => check!(KmacXof256Workspace),
                    _ => (),
                }
                Ok(())
            }

            pub(crate) fn dispatch(
                algorithm: &str,
                key: Fips202BitString<'_>,
                custom: Fips202BitString<'_>,
                message: Fips202BitString<'_>,
                output_bits: usize,
                output: &mut [u8],
                line: usize,
            ) -> Result<(), io::Error> {
                let valid = valid_bits(output_bits);
                match algorithm {
                    "kmac128" => Kmac128::$new_bits_conformance(key, custom)
                        .and_then(|state| {
                            state.$finalize_tag_bits_conformance(message, output, valid)
                        })
                        .map(|_| ())
                        .map_err(|_| invalid(line, "KMAC128 rejected bounded input")),
                    "kmac256" => Kmac256::$new_bits_conformance(key, custom)
                        .and_then(|state| {
                            state.$finalize_tag_bits_conformance(message, output, valid)
                        })
                        .map(|_| ())
                        .map_err(|_| invalid(line, "KMAC256 rejected bounded input")),
                    "kmacxof128" => xof128(key, custom, message, output, valid, line),
                    "kmacxof256" => xof256(key, custom, message, output, valid, line),
                    _ => Err(invalid(line, "unknown algorithm")),
                }
            }

            pub(crate) fn xof128(
                key: Fips202BitString<'_>,
                custom: Fips202BitString<'_>,
                message: Fips202BitString<'_>,
                output: &mut [u8],
                valid: u8,
                line: usize,
            ) -> Result<(), io::Error> {
                let destination = Fips202Output::new(output, valid)
                    .map_err(|_| invalid(line, "output shape rejected"))?;
                KmacXof128::$new_bits_conformance(key, custom)
                    .and_then(|state| state.$finalize_bits_xof_conformance(message))
                    .and_then(|reader| {
                        reader.squeeze_final_bits_public(
                            destination,
                            KmacPublicDeclassification::acknowledge(),
                        )
                    })
                    .map_err(|_| invalid(line, "KMACXOF128 rejected bounded input"))
            }

            pub(crate) fn xof256(
                key: Fips202BitString<'_>,
                custom: Fips202BitString<'_>,
                message: Fips202BitString<'_>,
                output: &mut [u8],
                valid: u8,
                line: usize,
            ) -> Result<(), io::Error> {
                let destination = Fips202Output::new(output, valid)
                    .map_err(|_| invalid(line, "output shape rejected"))?;
                KmacXof256::$new_bits_conformance(key, custom)
                    .and_then(|state| state.$finalize_bits_xof_conformance(message))
                    .and_then(|reader| {
                        reader.squeeze_final_bits_public(
                            destination,
                            KmacPublicDeclassification::acknowledge(),
                        )
                    })
                    .map_err(|_| invalid(line, "KMACXOF256 rejected bounded input"))
            }
        }
    };
}
profile!(
    conformance,
    brynja_mac_kmac::conformance,
    brynja_mac_kmac::conformance::hardened_in_place,
    with_bits_conformance,
    finalize_secret_bits_conformance,
    finalize_tag_bits_conformance,
    verify_bits_conformance,
    finalize_bits_xof_conformance,
    new_bits_conformance
);
profile!(
    production,
    brynja_mac_kmac,
    brynja_mac_kmac::hardened_in_place,
    with_bits,
    finalize_secret_bits,
    finalize_tag_bits,
    verify_bits,
    finalize_bits_xof,
    new_bits
);
