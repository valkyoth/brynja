use super::{Authority, Error};
use brynja_mac_hmac::execution::{Algorithm, Hmac};

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

impl Authority {
    /// Starts hardened HMAC on this selected owner.
    ///
    /// `Ok(None)` means an explicitly reported portable selection, before any
    /// key processing. Only that outcome permits choosing portable HMAC.
    /// `Err` never permits fallback, including in `Mode::Prefer`. The returned
    /// stream borrows this owner and rechecks its authority during execution.
    ///
    /// ```compile_fail
    /// use brynja_crypto_cpu_std::execution::Authority;
    /// use brynja_mac_hmac::{Sha256, execution::Hmac};
    /// fn escape(owner: Authority) -> Option<Hmac<'static, Sha256>> {
    ///     owner.hmac::<Sha256>(b"key").unwrap()
    /// }
    /// ```
    pub fn hmac<'a, A: Algorithm<'a>>(
        &'a self,
        key: &[u8],
    ) -> Result<Option<Hmac<'a, A>>, HmacError> {
        self.hmac_create(key, None)
    }

    /// Exact byte-prefix variant. On a portable selection `None` is returned
    /// without inspecting the key or validating the tag policy: the caller
    /// must pass the same policy to the portable constructor.
    pub fn hmac_with_tag_length<'a, A: Algorithm<'a>>(
        &'a self,
        key: &[u8],
        tag_bytes: usize,
    ) -> Result<Option<Hmac<'a, A>>, HmacError> {
        self.hmac_create(key, Some(tag_bytes))
    }

    fn hmac_create<'a, A: Algorithm<'a>>(
        &'a self,
        key: &[u8],
        tag_bytes: Option<usize>,
    ) -> Result<Option<Hmac<'a, A>>, HmacError> {
        match self.owner.as_ref() {
            None => Ok(None),
            Some(owner) => {
                // Readiness is checked before entering HMAC, and again by each
                // hardened hash session. No failed admission becomes None.
                let _ = owner
                    .session()
                    .map_err(|error| HmacError::Hosted(Error::Kernel(error)))?;
                let mac = match tag_bytes {
                    None => Hmac::from_runtime(owner, key),
                    Some(length) => Hmac::from_runtime_with_tag_length(owner, key, length),
                }
                .map_err(HmacError::Mac)?;
                Ok(Some(mac))
            }
        }
    }
}
