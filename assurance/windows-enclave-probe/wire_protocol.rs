//! Private wire parsing and terminal result admission for the public experiment.
use enclave_result::{Error, ResultHandle};

pub const INPUT: usize = 1072;
pub const COMMAND: usize = 64;

pub fn words<const N: usize>(bytes: &[u8]) -> Option<[u64; N]> {
    if bytes.len() != N.checked_mul(8)? {
        return None;
    }
    let mut result = [0; N];
    for (word, chunk) in result.iter_mut().zip(bytes.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().ok()?);
    }
    Some(result)
}

pub fn header(bytes: &[u8; INPUT]) -> Option<(usize, usize)> {
    let [version, reserved, length, address, width, flags] = words::<6>(&bytes[..48])?;
    if version != 2 || reserved != 0 || length > 1024 || width != 64 || flags != 0 || address == 0 {
        return None;
    }
    let address = usize::try_from(address).ok()?;
    address.checked_add(COMMAND)?;
    Some((usize::try_from(length).ok()?, address))
}

pub fn offer(token: [u64; 4], status: usize, bytes: &mut [u8; COMMAND]) {
    bytes.fill(0);
    for (value, out) in token
        .into_iter()
        .chain([status as u64])
        .zip(bytes.chunks_exact_mut(8))
    {
        out.copy_from_slice(&value.to_le_bytes());
    }
}

pub fn consume(
    handle: &mut ResultHandle<'_>,
    expected: [u64; 4],
    bytes: &[u8; COMMAND],
    write: impl FnOnce(usize, &[u8]) -> bool,
) -> usize {
    let Some([i0, i1, epoch, slot, action, flags, address, width]) = words::<8>(bytes) else {
        let _ = handle.cancel(handle.token());
        return 10;
    };
    let namespace = cfg!(probe_ignore_wire_identity) || [i0, i1] == expected[..2];
    let scope = cfg!(probe_ignore_wire_epoch) || epoch == expected[2];
    let destination = usize::try_from(address)
        .ok()
        .filter(|p| *p != 0 && p.checked_add(32).is_some());
    let valid_action = (action == 1 && width == 32 && destination.is_some())
        || (action == 2 && flags == 0 && address == 0 && width == 0);
    if !namespace || !scope || slot != expected[3] || !valid_action {
        return match handle.cancel(handle.token()) {
            Err(Error::Spent) => 21,
            _ => 10,
        };
    }
    let result = if action == 2 {
        handle.cancel(handle.token())
    } else {
        handle.export_public(handle.token(), flags, |data| {
            write(destination.unwrap_or(0), data)
        })
    };
    match result {
        Ok(()) => {
            if action == 1 {
                1
            } else {
                2
            }
        }
        Err(Error::Spent) => 21,
        Err(Error::Copy) => 12,
        Err(_) => 10,
    }
}
