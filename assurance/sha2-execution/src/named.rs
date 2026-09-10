use super::{Owner, checked, ensure};
use brynja_hash_sha2::{BitString, execution as api};

pub(super) fn quarantine_wide(owner: &Owner) -> Result<(), Box<dyn std::error::Error>> {
    if !matches!(
        owner.execution()?.route(),
        api::Route::Static(_) | api::Route::Runtime(_)
    ) {
        return Ok(());
    }
    let mut a = checked(api::Sha384::new(owner.execution()?))?;
    let mut b = checked(api::Sha512::new(owner.execution()?))?;
    let mut c = checked(api::Sha512_224::new(owner.execution()?))?;
    let mut d = checked(api::Sha512_256::new(owner.execution()?))?;
    let p = checked(brynja_hash_sha2::Sha512TBits::new(9))?;
    let mut e = checked(api::Sha512T::new(p, owner.execution()?))?;
    owner.quarantine();
    macro_rules! reject {
        ($stream:ident) => {{
            let report = $stream.report();
            ensure($stream.update(&[]).is_err())?;
            ensure($stream.update(&[0xa5; 256]).is_err())?;
            ensure($stream.message_bytes() == 0 && $stream.report() == report)?;
            ensure(
                $stream
                    .finalize_bits(checked(BitString::new(&[0x80], 1))?)
                    .is_err(),
            )?;
        }};
    }
    reject!(a);
    reject!(b);
    reject!(c);
    reject!(d);
    reject!(e);
    Ok(())
}

fn hex(text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if text.len() > 4096 || !text.len().is_multiple_of(2) {
        return Err("invalid fixed corpus".into());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let text = std::str::from_utf8(chunk)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}

macro_rules! check_named {
    ($name:ident, $owner:expr, $bytes:expr, $bits:expr, $expected:expr, $block_bits:expr) => {{
        let input = checked(BitString::new(
            $bytes,
            if $bits == 0 {
                0
            } else {
                (($bits - 1) % 8 + 1) as u8
            },
        ))?;
        let result = checked(api::$name::hash_bits($owner.execution()?, input))?;
        ensure(result.digest.as_bytes() == $expected)?;
        ensure(result.report.message_blocks == ($bits / $block_bits) as u128)?;
        let length_field = if $block_bits == 512 { 64 } else { 128 };
        ensure(
            result.report.padding_blocks
                == if $bits % $block_bits >= $block_bits - length_field {
                    2
                } else {
                    1
                },
        )?;
        if $bits % 8 == 0 {
            ensure(
                checked(api::$name::hash($owner.execution()?, $bytes))?
                    .digest
                    .as_bytes()
                    == $expected,
            )?;
        }
        for stride in [1, 19, 128] {
            let mut stream = checked(api::$name::new($owner.execution()?))?;
            for bytes in $bytes
                .get(..$bits / 8)
                .ok_or("invalid corpus")?
                .chunks(stride)
            {
                checked(stream.update(bytes))?;
            }
            let tail = checked(BitString::new(
                $bytes.get($bits / 8..).ok_or("invalid corpus")?,
                ($bits % 8) as u8,
            ))?;
            ensure(checked(stream.finalize_bits(tail))?.digest.as_bytes() == $expected)?;
        }
    }};
}

pub(super) fn run(narrow: &Owner, wide: &Owner) -> Result<usize, Box<dyn std::error::Error>> {
    let corpus =
        include_str!("../../../crates/brynja-hash-sha2/tests/vectors/nist-bit-selected.txt");
    let mut count = 0;
    for line in corpus
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
    {
        let fields: Vec<_> = line.split('|').collect();
        let [algorithm, bits, message, expected] = fields.as_slice() else {
            return Err("invalid fixed corpus".into());
        };
        let bits: usize = bits.parse()?;
        let storage = hex(message)?;
        let bytes = storage.get(..bits.div_ceil(8)).ok_or("invalid corpus")?;
        let expected = hex(expected)?;
        let expected = expected.as_slice();
        match *algorithm {
            "SHA224" => check_named!(Sha224, narrow, bytes, bits, expected, 512),
            "SHA256" => check_named!(Sha256, narrow, bytes, bits, expected, 512),
            "SHA384" => check_named!(Sha384, wide, bytes, bits, expected, 1024),
            "SHA512" => check_named!(Sha512, wide, bytes, bits, expected, 1024),
            "SHA512_224" => check_named!(Sha512_224, wide, bytes, bits, expected, 1024),
            "SHA512_256" => check_named!(Sha512_256, wide, bytes, bits, expected, 1024),
            _ => return Err("unexpected algorithm".into()),
        }
        count += 1;
    }
    ensure(count == 240)?;
    Ok(count)
}
