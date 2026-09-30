use super::*;
pub(super) fn reference(
    shape: Output,
    input: Bits<'_>,
    name: Bits<'_>,
    custom: Bits<'_>,
) -> Result<std::vec::Vec<u8>, Error> {
    use brynja_hash_sha3::*;
    let algorithm = shape.algorithm();
    let mut output = std::vec![0;shape.bytes()];
    match algorithm {
        Algorithm::Sha3_224 => output.copy_from_slice(
            sha3_224_bits(input)
                .map_err(|_| Error::Protocol)?
                .as_bytes(),
        ),
        Algorithm::Sha3_256 => output.copy_from_slice(
            sha3_256_bits(input)
                .map_err(|_| Error::Protocol)?
                .as_bytes(),
        ),
        Algorithm::Sha3_384 => output.copy_from_slice(
            sha3_384_bits(input)
                .map_err(|_| Error::Protocol)?
                .as_bytes(),
        ),
        Algorithm::Sha3_512 => output.copy_from_slice(
            sha3_512_bits(input)
                .map_err(|_| Error::Protocol)?
                .as_bytes(),
        ),
        Algorithm::Shake128 | Algorithm::Cshake128 => cshake128_bits(
            input,
            name,
            custom,
            Fips202Output::new(&mut output, shape.last()).map_err(|_| Error::Bounds)?,
        )
        .map_err(|_| Error::Protocol)?,
        Algorithm::Shake256 | Algorithm::Cshake256 => cshake256_bits(
            input,
            name,
            custom,
            Fips202Output::new(&mut output, shape.last()).map_err(|_| Error::Bounds)?,
        )
        .map_err(|_| Error::Protocol)?,
    }
    Ok(output)
}

#[test]
fn native_oracle_honors_zero_and_partial_output_shapes() -> Result<(), Error> {
    let empty = Bits::new(&[], 0).map_err(|_| Error::Bounds)?;
    for algorithm in [
        Algorithm::Shake128,
        Algorithm::Shake256,
        Algorithm::Cshake128,
        Algorithm::Cshake256,
    ] {
        for bits in [0_usize, 1, 7, 8, 9, 257] {
            let last = if bits == 0 {
                0
            } else {
                u8::try_from((bits - 1) % 8 + 1).map_err(|_| Error::Bounds)?
            };
            let shape = Output::new(algorithm, bits.div_ceil(8), last)?;
            let output = reference(shape, empty, empty, empty)?;
            assert_eq!(output.len(), shape.bytes());
            if let Some(byte) = output.last() {
                let mask = 0xff_u8
                    .checked_shr(u32::from(8 - last))
                    .ok_or(Error::Bounds)?;
                assert_eq!(*byte & !mask, 0);
            }
        }
    }
    Ok(())
}
