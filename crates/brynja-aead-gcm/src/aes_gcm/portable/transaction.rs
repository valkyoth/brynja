//! The single caller-output write boundary shared by portable seal and open.

pub(super) enum Buffers<'a> {
    Separate(&'a [u8], &'a mut [u8]),
    InPlace(&'a mut [u8]),
}

impl Buffers<'_> {
    pub(super) fn checked_input(&self, work_len: usize) -> Option<&[u8]> {
        let (input, dst_len): (&[u8], usize) = match self {
            Self::Separate(src, dst) => (src, dst.len()),
            Self::InPlace(buf) => (buf, buf.len()),
        };
        (input.len() == dst_len && input.len() == work_len).then_some(input)
    }

    pub(super) fn transact<T, E>(
        self,
        work: &mut [u8],
        bad_length: E,
        compute: impl FnOnce(&[u8], &mut [u8]) -> Result<T, E>,
    ) -> Result<T, E> {
        let input = self.checked_input(work.len()).ok_or(bad_length)?;
        // The callback can modify scratch, but cannot write the destination.
        let value = compute(input, work)?;
        let (Self::Separate(_, dst) | Self::InPlace(dst)) = self;
        dst.copy_from_slice(work);
        Ok(value)
    }
}
