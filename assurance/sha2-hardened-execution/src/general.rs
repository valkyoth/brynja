use super::{Owner, checked, ensure};
use brynja_hash_sha2::{BitString, Sha512TBits, hardened_execution::Sha512T};

pub(super) fn run(owner: &Owner) -> Result<usize, Box<dyn std::error::Error>> {
    let corpus =
        include_str!("../../../crates/brynja-hash-sha2/tests/vectors/general-sha512-t-digest.txt");
    let result =
        brynja_general_sha512_t_consumer::visit_corpus(corpus, |t, bits, bytes, expected| {
            let case = || -> Result<(), Box<dyn std::error::Error>> {
                let p = checked(Sha512TBits::new(t))?;
                let width = if bits == 0 {
                    0
                } else {
                    ((bits - 1) % 8 + 1) as u8
                };
                let input = checked(BitString::new(bytes, width))?;
                let output = checked(Sha512T::hash_bits_public(
                    p,
                    owner.execution()?,
                    input,
                    super::declassify(),
                ))?;
                ensure(output.digest.parameter() == p && output.digest.as_bytes() == expected)?;
                ensure(output.report.portable_iv_blocks == 1)?;
                ensure(output.report.message_blocks == (bits / 1024) as u128)?;
                ensure(output.report.padding_blocks == if bits % 1024 >= 896 { 2 } else { 1 })?;
                if bits % 8 == 0 {
                    let output = checked(Sha512T::hash_public(
                        p,
                        owner.execution()?,
                        bytes,
                        super::declassify(),
                    ))?;
                    ensure(output.digest.as_bytes() == expected)?;
                }
                let mut destination = vec![0xa5; p.output_bytes()];
                let secret = checked(Sha512T::hash_bits_secret(
                    p,
                    owner.execution()?,
                    input,
                    &mut destination,
                ))?;
                ensure(secret.digest.parameter() == p && secret.digest.as_bytes() == expected)?;
                drop(secret);
                ensure(destination.iter().all(|b| *b == 0))?;
                for stride in [1, 19, 128] {
                    let mut stream = checked(Sha512T::new(p, owner.execution()?))?;
                    let complete = bytes.get(..bits / 8).ok_or("invalid corpus")?;
                    for chunk in complete.chunks(stride) {
                        checked(stream.update(chunk))?;
                    }
                    let tail = bytes.get(bits / 8..).ok_or("invalid corpus")?;
                    let tail = checked(BitString::new(tail, (bits % 8) as u8))?;
                    ensure(
                        checked(stream.finalize_bits_public(tail, super::declassify()))?
                            .digest
                            .as_bytes()
                            == expected,
                    )?;
                }
                Ok(())
            };
            case().map_err(|_| brynja_general_sha512_t_consumer::acceptance::Error::Mismatch)
        });
    let count = checked(result)?;
    ensure(count == 4590)?;
    Ok(count)
}
