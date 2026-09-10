//! Fixed-size, project-owned real consumer; no evidence cfg or detector injection.
use brynja_crypto_cpu_std::execution as host;
use brynja_hash_sha2::hardened_execution as api;
use std::{error::Error, io};

mod general;
mod named;

fn declassify() -> api::PublicDeclassification {
    api::PublicDeclassification::acknowledge()
}

fn checked<T, E: std::fmt::Debug>(result: Result<T, E>) -> Result<T, Box<dyn Error>> {
    result.map_err(|e| io::Error::other(format!("acceptance failed: {e:?}")).into())
}
fn ensure(value: bool) -> Result<(), Box<dyn Error>> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other("acceptance failed: mismatch").into())
    }
}

enum Owner {
    Static(api::StaticSelection),
    Hosted(host::Authority),
}

impl Owner {
    fn new(mode: &str, wide: bool) -> Result<Self, Box<dyn Error>> {
        let kernel = if wide {
            api::Kernel::ArmSha512
        } else if cfg!(target_arch = "x86_64") {
            api::Kernel::X86Sha256
        } else {
            api::Kernel::ArmSha256
        };
        Ok(match mode {
            "portable" => Self::Static(checked(api::StaticSelection::new(
                kernel,
                api::Mode::Portable,
            ))?),
            "static" => Self::Static(checked(api::StaticSelection::new(
                kernel,
                api::Mode::Require,
            ))?),
            "hosted" => Self::Hosted(checked(host::Authority::new(kernel, host::Mode::Require))?),
            "prefer" => Self::Hosted(checked(host::Authority::new(kernel, host::Mode::Prefer))?),
            _ => return Err(io::Error::other("expected portable/static/hosted/prefer").into()),
        })
    }
    fn execution(&self) -> Result<api::Execution<'_>, Box<dyn Error>> {
        match self {
            Self::Static(owner) => checked(owner.hardened_execution()),
            Self::Hosted(owner) => Ok(match checked(owner.session())? {
                Some(session) => checked(api::Execution::from_runtime(session))?,
                None => api::Execution::portable(),
            }),
        }
    }
    fn quarantine(&self) {
        match self {
            Self::Static(owner) => owner.quarantine(),
            Self::Hosted(owner) => owner.quarantine(),
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() > 2 {
        return Err(io::Error::other("too many arguments").into());
    }
    let mode = args.first().map(String::as_str).unwrap_or("portable");
    let narrow_only = match args.get(1).map(String::as_str) {
        None => false,
        Some("narrow") => true,
        _ => return Err(io::Error::other("expected narrow or no second argument").into()),
    };
    let narrow = Owner::new(mode, false)?;
    let wide = if narrow_only {
        Owner::new("portable", true)?
    } else {
        Owner::new(mode, true)?
    };
    let count = named::run(&narrow, &wide)?;
    let general = general::run(&wide)?;
    let narrow_route = narrow.execution()?.route();
    let wide_route = wide.execution()?.route();
    named::quarantine_wide(&wide)?;
    if mode == "static" || mode == "hosted" {
        ensure(matches!(
            narrow_route,
            api::Route::Static(_) | api::Route::Runtime(_)
        ))?;
        if !narrow_only {
            ensure(matches!(
                wide_route,
                api::Route::Static(_) | api::Route::Runtime(_)
            ))?;
        }
    }
    let mut stream = checked(api::Sha256::new(narrow.execution()?))?;
    checked(stream.update(b"abc"))?;
    let previous = stream.report();
    narrow.quarantine();
    if matches!(narrow_route, api::Route::Static(_) | api::Route::Runtime(_)) {
        ensure(stream.update(b"later").is_err())?;
        ensure(stream.update(&[]).is_err())?;
        ensure(stream.message_bytes() == 0 && stream.report() == previous)?;
        let mut destination = [0xa5; 32];
        ensure(stream.finalize_secret(&mut destination).is_err())?;
        ensure(destination == [0; 32])?;
    }
    println!("SHA-2 hardened execution acceptance: PASS; named={count}; general={general}");
    println!("narrow={narrow_route:?}; wide={wide_route:?}");
    println!(
        "owned-memory cleanup; no register/spill guarantee; independently verified: NO; FIPS validated: NO"
    );
    Ok(())
}
