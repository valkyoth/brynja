use super::admission::{Candidate, Error, Mode};

/// Public low-level cross-crate bridge, not exported by the curated facade.
/// Direct users have the same stable-ISA requirement as the bounded owner.
/// This handle does not pin a thread or protect raw operands or results.
pub struct RuntimeProduct(Candidate);

/// Terminal startup or operation failure, never a fallback signal.
#[derive(Debug)]
pub struct Quarantined;

impl RuntimeProduct {
    /// Only absence of an admitted CPU bundle returns Ok(None).
    pub fn probe() -> Result<Option<Self>, Quarantined> {
        // Zbkc alone supplies both instructions but lacks native observations.
        // The checkout candidate can exercise it without admitting a public route.
        #[cfg(target_arch = "riscv64")]
        if !std::arch::is_riscv_feature_detected!("zbc") {
            return Ok(None);
        }
        let mut candidate = Candidate::detect();
        match candidate.select(Mode::Require) {
            Ok(_) => Ok(Some(Self(candidate))),
            Err(Error::Unavailable) => Ok(None),
            Err(_) => Err(Quarantined),
        }
    }

    /// Whether this owner may still accept or finish work.
    pub fn ready(&self) -> bool {
        self.0.ready()
    }

    /// Computes the next product without substituting portable multiplication.
    pub fn product(&mut self, x: u128, h: u128) -> Result<u128, Quarantined> {
        self.0.product(x, h).map_err(|_| Quarantined)
    }
}
