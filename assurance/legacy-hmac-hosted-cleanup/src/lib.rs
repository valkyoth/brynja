//! Real legacy host consumers; compiler emission is not native qualification.
#![forbid(unsafe_code)]

pub mod checkpoint;
pub mod normalization;
pub mod report;

#[cfg(target_os = "macos")]
use brynja_legacy_hmac_std::macos_resident as host;
#[cfg(target_os = "linux")]
use brynja_legacy_hmac_std::strict_execution as host;

macro_rules! scalar {
    ($name:ident, $algorithm:ty) => {
        pub mod $name {
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
        }
    };
}
scalar!(sha1, Sha1);
scalar!(md5, Md5);

pub mod sha1_compiled {
    use super::host::*;

    #[inline(never)]
    pub fn compute<'a>(
        session: &'a mut Sha1CompiledSession,
        request: Request<'_>,
        cancel: &Cancellation,
    ) -> Result<Output<'a, Sha1>, Error> {
        session.compute(request, cancel)
    }

    #[inline(never)]
    pub fn verify(
        session: &mut Sha1CompiledSession,
        request: Request<'_>,
        candidate: &[u8],
        cancel: &Cancellation,
    ) -> Result<bool, Error> {
        session.verify(request, candidate, cancel)
    }
}

pub mod md5_compiled {
    use super::host::*;

    #[inline(never)]
    pub fn compute<'a>(
        session: &'a mut Md5BatchSession,
        inputs: &[Option<Md5BatchInput<'_>>; 8],
        cancel: &Cancellation,
    ) -> Result<Md5BatchOutput<'a>, Error> {
        session.compute(inputs, cancel)
    }

    #[inline(never)]
    pub fn verify(
        session: &mut Md5BatchSession,
        inputs: &[Option<Md5BatchInput<'_>>; 8],
        candidates: &[Option<&[u8]>; 8],
        cancel: &Cancellation,
    ) -> Result<bool, Error> {
        session.verify(inputs, candidates, cancel)
    }
}
