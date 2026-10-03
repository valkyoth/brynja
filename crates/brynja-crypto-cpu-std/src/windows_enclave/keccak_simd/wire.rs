//! Version-22 metadata only; payload contents are inspected inside the enclave.
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
pub(in crate::windows_enclave) const PROTOCOL: usize = 0x42524235;

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
        inputs: &[Input<'_>; 4],
    ) -> Result<[u8; 384], Error> {
        if self.sequence == 0
            || !matches!(self.op, DIGEST | EXPORT | CANCEL)
            || (self.op != DIGEST && self.budget != 0)
        {
            return Err(Error::Bounds);
        }
        Plan::new(self.plan.0)?;
        let mut words = [0_u64; 48];
        words[..4].copy_from_slice(&[22, self.sequence, self.budget, 2]);
        for ((fields, slot), input) in words[4..].chunks_exact_mut(11).zip(self.plan.0).zip(inputs)
        {
            if self.op != CANCEL {
                *fields.get_mut(0).ok_or(Error::Bounds)? = slot.algorithm.wire();
                *fields.get_mut(1).ok_or(Error::Bounds)? =
                    u64::try_from(slot.output_bits).map_err(|_| Error::Bounds)?;
            }
            let parts = [&input.message, &input.name, &input.customization];
            for (index, (triple, part)) in fields
                .get_mut(2..)
                .ok_or(Error::Bounds)?
                .chunks_exact_mut(3)
                .zip(parts)
                .enumerate()
            {
                let length = part.bytes.len();
                if length == 0 {
                    if part.last != 0 {
                        return Err(Error::Bounds);
                    }
                    continue;
                }
                if self.op != DIGEST
                    || length > 1024
                    || !(1..=8).contains(&part.last)
                    || (index != 0
                        && !matches!(slot.algorithm, Algorithm::Cshake128 | Algorithm::Cshake256))
                {
                    return Err(Error::Bounds);
                }
                let source = part.bytes.as_ptr() as usize;
                source.checked_add(length).ok_or(Error::Bounds)?;
                triple.copy_from_slice(&[
                    u64::try_from(length).map_err(|_| Error::Bounds)?,
                    u64::from(part.last),
                    u64::try_from(source).map_err(|_| Error::Bounds)?,
                ]);
            }
        }
        let mut header = [0; 384];
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
pub(in crate::windows_enclave) fn payload_count(inputs: &[Input<'_>; 4]) -> usize {
    inputs
        .iter()
        .flat_map(|i| [&i.message, &i.name, &i.customization])
        .filter(|p| !p.bytes.is_empty())
        .count()
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
    expected_payloads: usize,
    value: [usize; 7],
) -> Result<(), Error> {
    if matches!(operation, 0 | 3) {
        return if value == [0; 7] && expected_payloads == 0 {
            Ok(())
        } else {
            Err(Error::Protocol)
        };
    }
    let [header, payload, clear, headers, payloads, exports, error] = value;
    if !matches!(operation, DIGEST | EXPORT | CANCEL)
        || expected_payloads > 12
        || (operation != DIGEST && expected_payloads != 0)
        || clear != 1
        || headers != 1
        || payloads != expected_payloads
        || exports != usize::from(operation == EXPORT)
        || error != 0
        || !super::super::protocol::regions(low, [header, payload], [384, 12288])
    {
        return Err(Error::Protocol);
    }
    Ok(())
}
