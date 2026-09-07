use brynja_legacy_md5::{BitString, Md5BatchControl};
use brynja_legacy_md5_std::RuntimeMd5Backend;
use brynja_legacy_sha1_std::RuntimeSha1Backend;

#[path = "../../legacy-hash-public-api/src/vectors.rs"]
mod frozen;

fn main() -> Result<(), &'static str> {
    if std::env::args_os().len() != 1 {
        return Err("no arguments accepted");
    }
    let count = brynja_legacy_hash_final_fixture::acceptance()?;
    if RuntimeSha1Backend::required().is_ok() || RuntimeMd5Backend::required().is_ok() {
        return Err("host observation admitted required acceleration");
    }
    let sha1 = RuntimeSha1Backend::opportunistic();
    let md5 = RuntimeMd5Backend::opportunistic();
    for (data, sha1_expected, md5_expected) in frozen::FILES {
        if sha1.hash(data).map_err(|_| "host SHA-1")? != *sha1_expected
            || md5.hash(data).map_err(|_| "host MD5")? != *md5_expected
        {
            return Err("host fallback differs from frozen vector");
        }
    }
    for (data, width, sha1_expected, md5_expected) in frozen::BITS {
        let bits = BitString::new(data, *width).map_err(|_| "bits")?;
        if sha1.hash_bits(bits).map_err(|_| "host SHA-1 bits")? != *sha1_expected
            || md5.hash_bits(bits).map_err(|_| "host MD5 bits")? != *md5_expected
        {
            return Err("host bit fallback differs from frozen vector");
        }
        let mut batch = [[0xa5; 16]; 8];
        let report = md5
            .batch(
                &[Some(bits); 8],
                &mut batch,
                &mut Md5BatchControl::new(8192),
            )
            .map_err(|_| "host batch")?;
        if batch.iter().any(|lane| lane.as_slice() != *md5_expected) || report.vector_blocks != 0 {
            return Err("host batch differs or executes instructions");
        }
    }
    println!("Legacy SHA-1/MD5 final public API acceptance: PASS");
    println!("frozen cases: 20; batch masks/cases: {count}; host required routes: rejected");
    println!("ordinary/hardened byte/bit: PASS; accelerated routes: 4 unadmitted");
    println!("collision-broken; no modern admission; independently verified: NO; FIPS: NO");
    Ok(())
}
