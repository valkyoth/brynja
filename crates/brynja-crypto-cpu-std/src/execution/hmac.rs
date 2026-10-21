use super::{Authority, Error};
use brynja_mac_hmac::execution::{Algorithm, Hmac};
use core::marker::PhantomData;

/// Hosted selection failure or a selected hardened HMAC failure.
/// Neither variant permits fallback after an accelerated owner was selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HmacError {
    /// The selected authority is no longer healthy.
    Hosted(Error),
    /// Required HMAC initialization failed.
    Mac(brynja_mac_hmac::Error),
}

/// Explicit routing result. Errors are never portable selections.
#[must_use]
pub enum HmacSelection<'a, A: Algorithm<'a>> {
    /// A keyed stream borrowing the selected authority.
    Accelerated(Hmac<'a, A>),
    /// No key has been processed; the validated algorithm/tag policy is retained.
    Portable(PortableHmac<A>),
}

/// Secret-free, validated portable policy. Its algorithm and tag width cannot
/// be replaced when starting the portable stream. No key is retained.
#[must_use]
pub struct PortableHmac<A: brynja_mac_hmac::Algorithm> {
    tag_bytes: Option<usize>,
    _algorithm: PhantomData<A>,
}
impl<A: brynja_mac_hmac::Algorithm> PortableHmac<A> {
    /// Starts portable HMAC with exactly the selected algorithm and tag policy.
    pub fn start(self, key: &[u8]) -> Result<brynja_mac_hmac::Hmac<A>, brynja_mac_hmac::Error> {
        match self.tag_bytes {
            None => brynja_mac_hmac::Hmac::new(key),
            Some(length) => brynja_mac_hmac::Hmac::with_tag_length(key, length),
        }
    }
    fn new(tag_bytes: Option<usize>) -> Result<Self, HmacError> {
        A::validate().map_err(HmacError::Mac)?;
        if let Some(bytes) = tag_bytes
            && (bytes < 16 || bytes.checked_mul(8).is_none_or(|bits| bits > A::TAG_BITS))
        {
            return Err(HmacError::Mac(brynja_mac_hmac::Error::TagLength));
        }
        Ok(Self {
            tag_bytes,
            _algorithm: PhantomData,
        })
    }
}

impl Authority {
    /// Starts hardened HMAC on this selected owner.
    ///
    /// `HmacSelection::Portable` reports portable selection before any key
    /// processing. Its token starts HMAC with the same validated tag policy.
    /// `Err` never permits fallback, including in `Mode::Prefer`. The returned
    /// stream borrows this owner and rechecks its authority during execution.
    ///
    /// ```compile_fail
    /// use brynja_crypto_cpu_std::execution::{Authority, HmacSelection};
    /// use brynja_mac_hmac::Sha256;
    /// fn escape(owner: Authority) -> HmacSelection<'static, Sha256> {
    ///     owner.hmac::<Sha256>(b"key").unwrap()
    /// }
    /// ```
    pub fn hmac<'a, A: Algorithm<'a>>(
        &'a self,
        key: &[u8],
    ) -> Result<HmacSelection<'a, A>, HmacError> {
        self.hmac_create(key, None)
    }

    /// Exact byte-prefix variant. Both routes validate the algorithm and width.
    /// A portable token retains the policy without inspecting the key.
    pub fn hmac_with_tag_length<'a, A: Algorithm<'a>>(
        &'a self,
        key: &[u8],
        tag_bytes: usize,
    ) -> Result<HmacSelection<'a, A>, HmacError> {
        self.hmac_create(key, Some(tag_bytes))
    }

    fn hmac_create<'a, A: Algorithm<'a>>(
        &'a self,
        key: &[u8],
        tag_bytes: Option<usize>,
    ) -> Result<HmacSelection<'a, A>, HmacError> {
        match self.owner.as_ref() {
            None => Ok(HmacSelection::Portable(PortableHmac::new(tag_bytes)?)),
            Some(owner) => {
                // Readiness is checked before entering HMAC, and again by each
                // hardened hash session. No failed admission becomes portable.
                let _ = owner
                    .session()
                    .map_err(|error| HmacError::Hosted(Error::Kernel(error)))?;
                let mac = match tag_bytes {
                    None => Hmac::from_runtime(owner, key),
                    Some(length) => Hmac::from_runtime_with_tag_length(owner, key, length),
                }
                .map_err(HmacError::Mac)?;
                Ok(HmacSelection::Accelerated(mac))
            }
        }
    }
}
