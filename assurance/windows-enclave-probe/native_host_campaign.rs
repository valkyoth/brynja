use super::*;
include!("native_vectors.rs");

pub(super) fn run(image: &[u16]) -> u32 {
    let Some(mut host) = Host::open(image) else {
        return 10;
    };
    for &(input, digest) in VECTORS {
        let mut output = [0xa5; 32];
        if host.execute(input, Disposition::ExportPublic(&mut output), 0) != Ok(Outcome::Exported)
            || output != *digest
        {
            return 11;
        }
        if host.execute(input, Disposition::Cancel, 0) != Ok(Outcome::Cancelled) {
            return 12;
        }
        output.fill(0xa5);
        if host.execute(input, Disposition::ExportPublic(&mut output), 4) != Err(Error::Copy)
            || output != [0xa5; 32]
            || host.session.state() != State::Ready
        {
            return 13;
        }
    }
    if !host.resource.close() {
        return 14;
    }
    if host.execute(b"abc", Disposition::Cancel, 0) != Err(Error::Quarantined) {
        return 15;
    }
    for fault in 1..=3 {
        let Some(mut host) = Host::open(image) else {
            return 20;
        };
        let mut output = [0xa5; 32];
        if host
            .execute(b"abc", Disposition::ExportPublic(&mut output), fault)
            .is_ok()
            || output != [0xa5; 32]
            || host.session.state() != State::Quarantined
        {
            return 21;
        }
        let calls = unsafe { HostCounter(2) };
        if host.execute(b"abc", Disposition::Cancel, 0) != Err(Error::Quarantined)
            || unsafe { HostCounter(2) } != calls
        {
            return 22;
        }
        if !host.resource.close() {
            return 23;
        }
    }
    // Exercise actual Drop deletion separately from explicit close.
    let Some(host) = Host::open(image) else {
        return 30;
    };
    drop(host);
    if unsafe { HostCounter(3) } != 0 || unsafe { HostCounter(4) } != 0 {
        return 31;
    }
    0
}
