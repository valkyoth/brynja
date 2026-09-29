use super::*;
include!("retained_native_vectors.rs");

pub(super) fn run(image: &[u16]) -> u32 {
    let Some(mut owner) = open(image, 0) else {
        return 10;
    };
    for (case, digest) in DIGESTS.iter().enumerate() {
        let mut output = [0xcc; 32];
        let Ok(pending) = owner.begin(PublicVector::new(case as u8).unwrap()) else {
            return 11;
        };
        if pending.export_public(&mut output).is_err() || output != *digest {
            return 12;
        }
        let Ok(pending) = owner.begin(PublicVector::new(case as u8).unwrap()) else {
            return 13;
        };
        if pending.cancel().is_err() {
            return 14;
        }
    }
    if owner.close().is_err() {
        return 15;
    }
    drop(owner);
    for forget in [false, true] {
        let Some(mut owner) = open(image, 0) else {
            return 20;
        };
        let Ok(pending) = owner.begin(PublicVector::new(1).unwrap()) else {
            return 21;
        };
        if forget {
            core::mem::forget(pending);
        } else {
            drop(pending);
        }
        if owner.state()
            != if forget {
                State::Busy
            } else {
                State::Quarantined
            }
        {
            return 22;
        }
        let before = unsafe { HostCounter(2) };
        if owner.begin(PublicVector::new(1).unwrap()).is_ok() || unsafe { HostCounter(2) } != before
        {
            return 23;
        }
        // Drop must clear the retained page before OS deletion.
        drop(owner);
    }
    for fault in 1..=3 {
        let Some(mut owner) = open(image, fault) else {
            return 30;
        };
        let Ok(pending) = owner.begin(PublicVector::new(1).unwrap()) else {
            return 31;
        };
        let mut output = [0xcc; 32];
        if pending.export_public(&mut output) != Err(Error::Protocol)
            || output != [0xcc; 32]
            || owner.state() != State::Quarantined
        {
            return 32;
        }
        if owner.begin(PublicVector::new(1).unwrap()).is_ok() {
            return 33;
        }
        if owner.close().is_err() {
            return 34;
        }
    }
    // Parent-only destruction also owns actual OS teardown.
    let Some(owner) = open(image, 0) else {
        return 40;
    };
    drop(owner);
    if unsafe { HostCounter(3) } != 0 || unsafe { HostCounter(4) } != 0 {
        return 41;
    }
    0
}
