use crate::static_execution::Error;

pub(super) fn offset(base: usize, back: usize) -> Result<usize, Error> {
    base.checked_sub(back).ok_or(Error::InternalDomain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedicated_sha512_offsets_reject_underflow() {
        assert_eq!(offset(16, 16), Ok(0));
        assert_eq!(offset(16, 17), Err(Error::InternalDomain));
        assert_eq!(offset(0, usize::MAX), Err(Error::InternalDomain));
    }
}
