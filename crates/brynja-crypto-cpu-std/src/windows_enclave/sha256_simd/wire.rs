//! Version-21 bounded metadata only. Payload bytes are copied by the enclave.
use super::{Algorithm, Error, Input, Plan};
pub(super) const DIGEST: usize = 100;
pub(super) const EXPORT: usize = 101;
pub(super) const CANCEL: usize = 102;
#[cfg(any(
    test,
    all(
        target_os = "windows",
        target_arch = "x86_64",
        target_env = "msvc",
        not(miri),
        not(kani)
    )
))]
pub(in crate::windows_enclave) const PROTOCOL: usize = 0x42524234;

pub(super) fn identity(algorithm: Algorithm) -> Result<u64, Error> {
    Ok(match algorithm.wire() {
        1 => 224,
        2 => 256,
        _ => return Err(Error::Bounds),
    })
}

#[derive(Clone, Copy)]
pub(in crate::windows_enclave) struct Request {
    pub op: usize,
    pub sequence: u64,
    pub budget: u64,
    pub plan: Plan,
}
impl Request {
    pub(in crate::windows_enclave) fn header(
        self,
        inputs: &[Input<'_>; 8],
    ) -> Result<[u8; 288], Error> {
        if self.sequence == 0
            || !matches!(self.op, DIGEST | EXPORT | CANCEL)
            || (self.op != DIGEST && self.budget != 0)
        {
            return Err(Error::Bounds);
        }
        let mut words = [0_u64; 36];
        words[..4].copy_from_slice(&[21, self.sequence, self.budget, 2]);
        for ((fields, algorithm), input) in
            words[4..].chunks_exact_mut(4).zip(self.plan.0).zip(inputs)
        {
            if self.op != DIGEST && (!input.bytes.is_empty() || input.last != 0) {
                return Err(Error::Bounds);
            }
            if self.op == CANCEL {
                continue;
            }
            *fields.get_mut(0).ok_or(Error::Bounds)? = identity(algorithm)?;
            if self.op == DIGEST {
                let length = input.bytes.len();
                if !(64..=1024).contains(&length)
                    || !(1..=8).contains(&input.last)
                    || (length == 64 && input.last != 8)
                {
                    return Err(Error::Bounds);
                }
                let source = input.bytes.as_ptr() as usize;
                source.checked_add(length).ok_or(Error::Bounds)?;
                *fields.get_mut(1).ok_or(Error::Bounds)? =
                    u64::try_from(length).map_err(|_| Error::Bounds)?;
                *fields.get_mut(2).ok_or(Error::Bounds)? = u64::from(input.last);
                *fields.get_mut(3).ok_or(Error::Bounds)? =
                    u64::try_from(source).map_err(|_| Error::Bounds)?;
            }
        }
        let mut header = [0; 288];
        for (word, bytes) in words.into_iter().zip(header.chunks_exact_mut(8)) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        Ok(header)
    }
}

#[cfg(any(
    test,
    all(
        target_os = "windows",
        target_arch = "x86_64",
        target_env = "msvc",
        not(miri),
        not(kani)
    )
))]
pub(in crate::windows_enclave) fn receipt(
    low: usize,
    operation: usize,
    value: [usize; 7],
) -> Result<(), Error> {
    if matches!(operation, 0 | 3) {
        return if value == [0; 7] {
            Ok(())
        } else {
            Err(Error::Protocol)
        };
    }
    let [header, payload, clear, headers, payloads, exports, error] = value;
    if !matches!(operation, DIGEST | EXPORT | CANCEL)
        || clear != 1
        || headers != 1
        || payloads != if operation == DIGEST { 8 } else { 0 }
        || exports != usize::from(operation == EXPORT)
        || error != 0
        || !super::super::protocol::regions(low, [header, payload], [288, 8192])
    {
        return Err(Error::Protocol);
    }
    Ok(())
}
