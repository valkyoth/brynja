//! Bounded public-data-only downstream driver; no external oracle dependency.
use brynja_crypto_cpu_std::keccak_batch::Authority;
use brynja_hash_sha3::{
    Fips202BitString,
    batch::{Algorithm, Control, Input, Mode, PublicData, Workspace},
};
use std::{
    fmt::Write as _,
    io::{self, Read as _},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_BYTES: u64 = 8 * 1024 * 1024;
struct Request {
    algorithm: Algorithm,
    message: Vec<u8>,
    name: Vec<u8>,
    custom: Vec<u8>,
    bits: [usize; 4],
}

fn bits(bytes: &[u8], n: usize) -> Result<Fips202BitString<'_>> {
    if bytes.len() != n.div_ceil(8) {
        return Err("length mismatch".into());
    }
    let valid = if n == 0 {
        0
    } else {
        u8::try_from((n - 1) % 8 + 1)?
    };
    Fips202BitString::new(bytes, valid).map_err(|e| format!("invalid bits: {e:?}").into())
}
fn hex(text: &str) -> Result<Vec<u8>> {
    if text == "-" {
        return Ok(Vec::new());
    }
    if !text.is_ascii() || !text.len().is_multiple_of(2) || text.len() > 8192 {
        return Err("hex shape".into());
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let s = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(s, 16)?)
        })
        .collect()
}
fn parse(text: &str) -> Result<Request> {
    let fields: Vec<_> = text.split_whitespace().collect();
    let [algorithm, m, n, s, o, message, name, custom] = fields.as_slice() else {
        return Err("field count".into());
    };
    let algorithm = match *algorithm {
        "sha3-224" => Algorithm::Sha3_224,
        "sha3-256" => Algorithm::Sha3_256,
        "sha3-384" => Algorithm::Sha3_384,
        "sha3-512" => Algorithm::Sha3_512,
        "shake128" => Algorithm::Shake128,
        "shake256" => Algorithm::Shake256,
        "cshake128" => Algorithm::Cshake128,
        "cshake256" => Algorithm::Cshake256,
        _ => return Err("unknown identity".into()),
    };
    let lengths: Vec<usize> = [m, n, s, o]
        .into_iter()
        .map(|value| value.parse())
        .collect::<std::result::Result<_, _>>()?;
    let [m, n, s, o] = lengths.as_slice() else {
        return Err("length count".into());
    };
    if [m, n, s, o].into_iter().any(|n| *n > 32768) {
        return Err("length bound".into());
    }
    Ok(Request {
        algorithm,
        message: hex(message)?,
        name: hex(name)?,
        custom: hex(custom)?,
        bits: [*m, *n, *s, *o],
    })
}
impl Request {
    fn input(&self) -> Result<Input<'_>> {
        let [m, n, s, o] = self.bits;
        Input::with_customization(
            self.algorithm,
            bits(&self.message, m)?,
            bits(&self.name, n)?,
            bits(&self.custom, s)?,
            o,
        )
        .map_err(|e| format!("request: {e:?}").into())
    }
}
fn main() -> Result<()> {
    let mode = match std::env::args().nth(1).as_deref() {
        Some("portable") => Mode::Portable,
        Some("prefer") => Mode::Prefer,
        Some("required") => Mode::Require,
        _ => return Err("mode required".into()),
    };
    let owner = Authority::new(mode).map_err(|e| format!("authority: {e:?}"))?;
    let executor = owner.executor(1).map_err(|e| format!("executor: {e:?}"))?;
    let mut campaign = String::new();
    io::stdin()
        .take(MAX_BYTES + 1)
        .read_to_string(&mut campaign)?;
    if campaign.len() as u64 > MAX_BYTES {
        return Err("campaign bound".into());
    }
    let mut rendered = String::new();
    let mut vector_calls = 0_u64;
    let mut batches = 0_usize;
    let mut workspace = Workspace::new();
    for line in campaign.lines() {
        batches = batches.checked_add(1).ok_or("batch counter")?;
        if batches > 1024 || line.len() > 100_000 {
            return Err("case bound".into());
        }
        let requests: Vec<_> = line.split(';').map(parse).collect::<Result<_>>()?;
        if requests.len() > 4 {
            return Err("batch capacity".into());
        }
        let inputs: Vec<_> = requests.iter().map(Request::input).collect::<Result<_>>()?;
        let mut storage: Vec<_> = inputs
            .iter()
            .map(|i| vec![0xa5; i.output_bytes()])
            .collect();
        let mut output: Vec<_> = storage.iter_mut().map(Vec::as_mut_slice).collect();
        let total = inputs
            .iter()
            .try_fold(0_usize, |n, i| n.checked_add(i.output_bytes()))
            .ok_or("output bound")?;
        let mut staging = vec![0x5a; total];
        let mut cancel = || false;
        let report = executor
            .digest(
                PublicData::new(inputs.as_slice()),
                &mut output,
                &mut workspace,
                &mut staging,
                &mut Control::new(4096, &mut cancel),
            )
            .map_err(|e| format!("execution: {e:?}"))?;
        vector_calls = vector_calls
            .checked_add(report.vector_calls)
            .ok_or("vector counter")?;
        for (i, bytes) in storage.iter().enumerate() {
            if i != 0 {
                rendered.push(';');
            }
            for byte in bytes {
                write!(rendered, "{byte:02x}")?;
            }
        }
        rendered.push('\n');
    }
    print!("{rendered}");
    eprintln!("KECCAK_BATCH_ACCEPTANCE: batches={batches}; vector_calls={vector_calls}");
    Ok(())
}
