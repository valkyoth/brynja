#[path = "../../../crates/brynja-hash-sha3/tests/execution_cases/mod.rs"]
mod cases;
#[path = "../../../crates/brynja-hash-sha3/tests/cshake_execution_cases/mod.rs"]
mod cshake_cases;
use brynja_crypto_cpu_std::sponge as hosted;
use brynja_hash_sha3::execution as api;

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args()
        .nth(1)
        .ok_or("expected portable, prefer, static or hosted")?;
    let kernel = if cfg!(target_arch = "aarch64") {
        api::Kernel::ArmKeccak
    } else {
        api::Kernel::X86Keccak
    };
    let selection = api::StaticSelection::new(
        kernel,
        if mode == "static" {
            api::Mode::Require
        } else {
            api::Mode::Portable
        },
    )?;
    let host = hosted::Sponge::new(
        match mode.as_str() {
            "hosted" => hosted::Mode::Require,
            "prefer" => hosted::Mode::Prefer,
            "static" | "portable" => hosted::Mode::Portable,
            _ => return Err("unknown mode".into()),
        },
    )
    .map_err(|error| format!("hosted selection: {error:?}"))?;
    let route = || -> Result<api::Execution<'_>, Box<dyn std::error::Error>> {
        if mode == "static" {
            return Ok(selection.execution()?);
        }
        Ok(host.execution()?)
    };
    let selected = route()?.route();
    let count = cases::run(route)?;
    let cshake_count = cshake_cases::run(route)?;
    // Verify live owner loss also invalidates a reader before any output write.
    let mut reader = api::Shake128::new(route()?)?.finalize_xof()?;
    if matches!(selected, api::Route::Static(_) | api::Route::Runtime(_)) {
        selection.quarantine();
        host.quarantine();
        let mut output = [0xa5; 400];
        if reader
            .squeeze_with_scratch(&mut output, &mut [0; 400])
            .is_ok()
            || output != [0xa5; 400]
        {
            return Err("quarantine/output transaction bypass".into());
        }
    }
    println!("SHA-3/SHAKE ordinary execution: PASS; cases={count}; route={selected:?}");
    println!("cSHAKE ordinary execution: PASS; cases={cshake_count}; route={selected:?}");
    println!("hosted selection: {:?}", host.report().route);
    println!("public-only; independently verified: NO; FIPS validated: NO");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("acceptance failed: {error}");
        std::process::exit(1);
    }
}
