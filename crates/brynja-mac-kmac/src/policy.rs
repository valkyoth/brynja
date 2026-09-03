/// Key-strength classification retained by a KMAC state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KmacKeyPolicy {
    /// The key is at least as long as the selected KMAC security strength.
    FullStrength,
    /// The key is standards-valid but shorter than the selected strength.
    ConformanceOnly,
}

/// Security classification of one fixed KMAC tag length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KmacTagPolicy {
    /// The tag is at least as long as the selected KMAC security strength.
    FullStrength,
    /// The tag is at least 64 bits but below the selected security strength.
    ReducedStrength,
    /// The tag is 32 through 63 bits and requires application risk analysis.
    RiskManagedShort,
    /// The tag is below the 32-bit SP 800-185 MAC minimum.
    ConformanceOnly,
}

/// Current module-service status for every KMAC operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KmacServiceStatus {
    /// The implementation has no FIPS 140-3 validation or approved provider effect.
    NonApproved,
}

pub(crate) fn key_policy(bits: u128, strength: u128) -> KmacKeyPolicy {
    if bits >= strength {
        KmacKeyPolicy::FullStrength
    } else {
        KmacKeyPolicy::ConformanceOnly
    }
}

pub(crate) fn tag_policy(bits: u128, strength: u128) -> KmacTagPolicy {
    if bits >= strength {
        KmacTagPolicy::FullStrength
    } else if bits >= 64 {
        KmacTagPolicy::ReducedStrength
    } else if bits >= 32 {
        KmacTagPolicy::RiskManagedShort
    } else {
        KmacTagPolicy::ConformanceOnly
    }
}

#[cfg(kani)]
mod proofs {
    use super::{KmacKeyPolicy, KmacTagPolicy, key_policy, tag_policy};

    #[kani::proof]
    fn key_classifier_has_exact_boundary() {
        let bits = kani::any::<u128>();
        let strength = kani::any::<u128>();
        assert_eq!(
            key_policy(bits, strength) == KmacKeyPolicy::FullStrength,
            bits >= strength
        );
    }

    #[kani::proof]
    fn tag_classifier_partitions_the_complete_domain() {
        let bits = kani::any::<u128>();
        let strength = kani::any::<u128>();
        kani::assume(strength >= 64);
        let expected = if bits >= strength {
            KmacTagPolicy::FullStrength
        } else if bits >= 64 {
            KmacTagPolicy::ReducedStrength
        } else if bits >= 32 {
            KmacTagPolicy::RiskManagedShort
        } else {
            KmacTagPolicy::ConformanceOnly
        };
        assert_eq!(tag_policy(bits, strength), expected);
    }
}
