//! Offline inspection, not authorization: its output must be reviewed separately.
mod image_admission;
use std::io::Read;
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let mode = args.next().ok_or("mode required")?;
    let path = args.next().ok_or("image required")?;
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > 16 * 1024 * 1024 {
        return Err("oversized image".into());
    }
    let mut b = Vec::new();
    file.take(16 * 1024 * 1024 + 1).read_to_end(&mut b)?;
    if mode == "prepare" {
        let destination = args.next().ok_or("new output path required")?;
        if args.next().is_some() {
            return Err("extra argument".into());
        }
        let length = image_admission::prepare_windows_imports(&mut b)
            .map_err(|e| format!("prepare rejected: {e:?}"))?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        std::io::Write::write_all(&mut file, &b[..length])?;
        println!(
            "Unsigned Windows-import image prepared; sign then inspect (VEIID must run BEFORE this transform)"
        );
        return Ok(());
    }
    if mode != "inspect" || args.next().is_some() {
        return Err("invalid command".into());
    }
    let id = image_admission::inspect(&b).map_err(|e| format!("image rejected: {e:?}"))?;
    let hash = brynja_hash_sha2::sha256(&b).map_err(|_| "hash rejected")?;
    let policy = image_admission::Policy {
        digest: *hash.as_bytes(),
        identity: id,
    };
    image_admission::admit(&b, &policy).map_err(|_| "internal comparison failed")?;
    println!(
        "{{\"status\":\"UNTRUSTED_INSPECTION\",\"sha256\":{:?},\"family\":{:?},\"image\":{:?},\"version\":{},\"security\":{},\"policy\":{},\"size\":{},\"threads\":{},\"minimum_import_security\":{:?}}}",
        hash.as_bytes(),
        id.family,
        id.image,
        id.version,
        id.security,
        id.policy,
        id.size,
        id.threads,
        id.minimum_import_security
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
