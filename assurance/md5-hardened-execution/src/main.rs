//! Bounded public batch adapter: eight bits:hex fields; ~ means inactive.
use brynja_legacy_md5::{
    BitString, Md5BatchControl, PublicDeclassification,
    hardened_execution::{Executor, Mode},
};
use std::{
    error::Error,
    io::{self, BufRead, Read},
};

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid bounded MD5 batch request",
    )
}

fn execute(executor: &Executor, line: &[u8]) -> Result<(), Box<dyn Error>> {
    let text = core::str::from_utf8(line)?;
    let mut fields = text.split_whitespace();
    let mut storage = [[0u8; 1024]; 8];
    let mut inputs = [None; 8];
    for (bytes, input) in storage.iter_mut().zip(inputs.iter_mut()) {
        let field = fields.next().ok_or_else(invalid)?;
        if field == "~" {
            continue;
        }
        let (length, hex) = field.split_once(':').ok_or_else(invalid)?;
        let length: usize = length.parse().map_err(|_| invalid())?;
        if length > 8192 {
            return Err(invalid().into());
        }
        let size = length.div_ceil(8);
        let hex = if hex == "-" { "" } else { hex };
        if hex.len() != size * 2 {
            return Err(invalid().into());
        }
        let bytes = bytes.get_mut(..size).ok_or_else(invalid)?;
        for (byte, pair) in bytes
            .iter_mut()
            .zip(hex.as_bytes().as_chunks::<2>().0.iter())
        {
            *byte = u8::from_str_radix(core::str::from_utf8(pair)?, 16).map_err(|_| invalid())?;
        }
        let valid = if length == 0 {
            0
        } else {
            u8::try_from((length - 1) % 8 + 1)?
        };
        *input = Some(BitString::new(bytes, valid).map_err(|_| invalid())?);
    }
    if fields.next().is_some() {
        return Err(invalid().into());
    }
    let mut output = [[0xa5; 16]; 8];
    let report = executor.batch().digest_public(
        &inputs,
        &mut output,
        &mut Md5BatchControl::new(144),
        PublicDeclassification::acknowledge(),
    )?;
    // Fixture input is public synthetic oracle data, not a deployment secret log.
    let mut secret = [[0xa5; 16]; 8];
    let (owned, secret_report) =
        executor
            .batch()
            .digest_secret(&inputs, &mut secret, &mut Md5BatchControl::new(144))?;
    if owned.expose() != output.as_flattened() || secret_report != report {
        return Err(invalid().into());
    }
    drop(owned);
    if secret != [[0; 16]; 8] {
        return Err(invalid().into());
    }
    let mut workspace = brynja_legacy_md5::hardened_execution::in_place::Workspace::new(executor);
    let mut scoped = output.map(|lane| lane.map(|byte| !byte));
    let scoped_report = workspace.with(|batch| {
        batch.digest_public(
            &inputs,
            &mut scoped,
            &mut Md5BatchControl::new(144),
            PublicDeclassification::acknowledge(),
        )
    })??;
    if scoped != output || scoped_report != report {
        return Err(invalid().into());
    }
    secret.fill([0xa5; 16]);
    let (owned, scoped_report) = workspace.with(|batch| {
        batch.digest_secret(&inputs, &mut secret, &mut Md5BatchControl::new(144))
    })??;
    if owned.expose() != output.as_flattened() || scoped_report != report {
        return Err(invalid().into());
    }
    drop(owned);
    if secret != [[0; 16]; 8] {
        return Err(invalid().into());
    }
    for lane in output {
        for byte in lane {
            print!("{byte:02x}");
        }
        print!(" ");
    }
    println!(
        "{} {} {}",
        report.vector_width, report.work.vector_blocks, report.work.scalar_blocks
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let mode = arguments.next().ok_or_else(invalid)?;
    if arguments.next().is_some() {
        return Err(invalid().into());
    }
    let executor = match mode.as_str() {
        "portable" => Executor::portable(),
        "prefer" => Executor::for_compiled_target(Mode::Prefer)?,
        "require" => Executor::for_compiled_target(Mode::Require)?,
        "hosted" => brynja_legacy_md5_std::hardened_execution::select(Mode::Prefer)?,
        _ => return Err(invalid().into()),
    };
    let mut input = io::stdin().lock();
    for _ in 0..4096 {
        let mut line = Vec::new();
        line.try_reserve_exact(32768)?;
        let read = (&mut input).take(32768).read_until(b'\n', &mut line)?;
        if read == 0 {
            return Ok(());
        }
        if read == 32768 {
            return Err(invalid().into());
        }
        execute(&executor, &line)?;
    }
    // Exact request limit: do not process or emit a 4097th batch.
    if input.fill_buf()?.is_empty() {
        Ok(())
    } else {
        Err(invalid().into())
    }
}
