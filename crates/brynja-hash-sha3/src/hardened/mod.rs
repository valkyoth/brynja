mod cshake;
mod fixed;
mod output;
mod owner;
mod permutation;
mod sponge;
mod xof;

pub use fixed::{HardenedSha3_224, HardenedSha3_256, HardenedSha3_384, HardenedSha3_512};
pub use output::{HardenedSha3Error, HardenedSha3SecretOutput, Sha3PublicDeclassification};
pub use xof::{HardenedShake128, HardenedShake128Reader, HardenedShake256, HardenedShake256Reader};

mod sealed {
    pub trait Registered {}
    pub trait Construction {}
}

/// Sealed capability implemented only by hardened FIPS 202 states.
///
/// Downstream crates cannot implement this marker for an ordinary or
/// non-erasing wrapper.
///
/// ```compile_fail
/// use brynja_hash_sha3::HardenedFips202State;
/// struct Forged;
/// impl HardenedFips202State for Forged {}
/// ```
pub trait HardenedFips202State: sealed::Registered {}

/// Sealed construction-owner capability for hardened absorbing states.
///
/// This marker exposes no sponge lane, permutation, suffix, or snapshot. It
/// lets later in-crate cSHAKE/KMAC and purpose-specific public constructions
/// distinguish the reviewed erasing owner from ordinary states.
pub trait HardenedFips202Construction: HardenedFips202State + sealed::Construction {}

macro_rules! register_state {
    ($name:ty) => {
        impl sealed::Registered for $name {}
        impl HardenedFips202State for $name {}
    };
}

macro_rules! register_construction {
    ($name:ty) => {
        register_state!($name);
        impl sealed::Construction for $name {}
        impl HardenedFips202Construction for $name {}
    };
}

register_construction!(HardenedSha3_224);
register_construction!(HardenedSha3_256);
register_construction!(HardenedSha3_384);
register_construction!(HardenedSha3_512);
register_construction!(HardenedShake128);
register_state!(HardenedShake128Reader);
register_construction!(HardenedShake256);
register_state!(HardenedShake256Reader);
register_construction!(HardenedCshake128);
register_state!(HardenedCshake128Reader);
register_construction!(HardenedCshake256);
register_state!(HardenedCshake256Reader);
pub use cshake::{
    HardenedCshake128, HardenedCshake128Reader, HardenedCshake256, HardenedCshake256Reader,
};
