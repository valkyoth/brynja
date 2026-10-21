//! Real host-to-worker HMAC consumers; emission is not native qualification.
#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
use brynja_crypto_cpu_std::macos_resident::hmac as host;
#[cfg(target_os = "linux")]
use brynja_crypto_cpu_std::strict_hmac as host;

macro_rules! probes {
    ($module:ident, $algorithm:ty) => {
        pub mod $module {
            use super::host::*;

            #[inline(never)]
            pub fn compute<'a>(
                session: &'a mut Session<$algorithm>,
                request: Request<'_>,
                cancel: &Cancellation,
            ) -> Result<Output<'a, $algorithm>, Error> {
                session.compute(request, cancel)
            }

            #[inline(never)]
            pub fn verify(
                session: &mut Session<$algorithm>,
                request: Request<'_>,
                candidate: &[u8],
                cancel: &Cancellation,
            ) -> Result<bool, Error> {
                session.verify(request, candidate, cancel)
            }

            #[inline(never)]
            pub fn compiled_compute<'a>(
                session: &'a mut CompiledSession<$algorithm>,
                request: Request<'_>,
                cancel: &Cancellation,
            ) -> Result<Output<'a, $algorithm>, Error> {
                session.compute(request, cancel)
            }

            #[inline(never)]
            pub fn compiled_verify(
                session: &mut CompiledSession<$algorithm>,
                request: Request<'_>,
                candidate: &[u8],
                cancel: &Cancellation,
            ) -> Result<bool, Error> {
                session.verify(request, candidate, cancel)
            }
        }
    };
}

probes!(sha224, Sha224);
probes!(sha256, Sha256);
probes!(sha384, Sha384);
probes!(sha512, Sha512);
probes!(sha512_224, Sha512_224);
probes!(sha512_256, Sha512_256);
probes!(sha3_224, Sha3_224);
probes!(sha3_256, Sha3_256);
probes!(sha3_384, Sha3_384);
probes!(sha3_512, Sha3_512);
probes!(general129, Sha512T<129>);
probes!(general511, Sha512T<511>);
