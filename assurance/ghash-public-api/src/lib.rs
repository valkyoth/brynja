#![no_std]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

// Generated in the isolated consumer: only a re-export of the public module.
include!("route.rs");

/// Hash caller-framed blocks into a typed, caller-owned secret result.
pub fn framed<'a>(
    h: &[u8; 16],
    workspace: &mut [u8; 16],
    bytes: &[u8],
    output: &'a mut [u8; 16],
) -> Result<ghash::SecretHash<'a>, ghash::Error> {
    let budget = u64::try_from(bytes.len()).map_err(|_| ghash::Error::LimitExceeded)?;
    let mut state = ghash::Ghash::new(h, workspace, budget);
    state.update(bytes)?;
    state.finish(output)
}
