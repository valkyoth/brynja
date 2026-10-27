use crate::{Algorithm, Error, Hmac, SecretTag, Tag};

impl<A: Algorithm> Hmac<A> {
    /// Authenticates one canonical bit message with a byte-string key.
    ///
    /// SHA-2 accepts [`crate::Sha2BitString`] (high bits of a partial byte);
    /// SHA-3 accepts [`crate::Fips202BitString`] (low bits of a partial byte).
    /// These types are not interchangeable. Constructors reject noncanonical
    /// unused bits; that validation is observable and does not clear the input.
    ///
    /// The returned tag is the complete digest; `bit_len` reports its exact
    /// width (general SHA-512/t may end in a partial byte). This does not add
    /// fractional keys, arbitrary bit truncation or a message-length preflight.
    ///
    /// ```
    /// use brynja_mac_hmac::{Hmac, Sha256, Sha2BitString};
    /// let message = Sha2BitString::new(&[0xa0], 3).expect("canonical literal");
    /// let mut output = [0; 32];
    /// let tag = Hmac::<Sha256>::authenticate_bits(b"example key", message, &mut output)?;
    /// assert_eq!(Hmac::<Sha256>::new(b"example key")?
    ///     .verify_bits(message, tag.as_bytes()), Ok(()));
    /// # Ok::<(), brynja_mac_hmac::Error>(())
    /// ```
    pub fn authenticate_bits<'out>(
        key: &[u8],
        message: A::FinalInput<'_>,
        destination: &'out mut [u8],
    ) -> Result<Tag<'out, A>, Error> {
        Self::new(key)?.finalize_bits_tag(message, destination)
    }

    /// Consumes the stream with final message bits and releases a public tag.
    ///
    /// Bytes previously supplied to `update` precede this final bit string.
    /// The tag length remains the previously selected byte policy. On any
    /// failure the public destination is unchanged; the stream is consumed.
    pub fn finalize_bits_tag<'out>(
        self,
        input: A::FinalInput<'_>,
        destination: &'out mut [u8],
    ) -> Result<Tag<'out, A>, Error> {
        self.engine.public(Some(input), destination)
    }

    /// Consumes the stream with final message bits and returns clearing output.
    ///
    /// Every finalization error clears the whole destination. Dropping the
    /// returned owner clears it too, including during recoverable unwinding.
    /// Caller-owned input buffers remain outside this cleanup boundary.
    pub fn finalize_bits_secret<'out>(
        self,
        input: A::FinalInput<'_>,
        destination: &'out mut [u8],
    ) -> Result<SecretTag<'out, A>, Error> {
        self.engine.secret(Some(input), destination)
    }

    /// Consumes the stream with final message bits and verifies an exact tag.
    ///
    /// Comparison and public-length rejection follow the same policy as
    /// `verify`: all equal-length bytes are compared, with no early exit on
    /// a mismatch. No input-length preflight oracle is provided.
    pub fn verify_bits(self, input: A::FinalInput<'_>, candidate: &[u8]) -> Result<(), Error> {
        self.engine.verify(Some(input), candidate)
    }
}
