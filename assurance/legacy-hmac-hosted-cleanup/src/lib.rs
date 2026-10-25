//! Real legacy host consumers; compiler emission is not native qualification.
#![forbid(unsafe_code)]

pub mod admission;
pub mod checkpoint;
pub mod control;
pub mod decision;
pub mod lane;
pub mod normalization;
pub mod report;
pub mod report_result;
pub mod tag_copy;
pub mod verification;

#[cfg(target_os = "macos")]
use brynja_legacy_hmac_std::macos_resident as host;
#[cfg(target_os = "linux")]
use brynja_legacy_hmac_std::strict_execution as host;

macro_rules! output_loan {
    ($algorithm:ty) => {
        #[inline(never)]
        pub fn output_expose<'a>(output: &'a Output<'_, $algorithm>) -> &'a [u8] {
            output.expose()
        }

        #[inline(never)]
        pub fn output_declassify(
            output: Output<'_, $algorithm>,
            destination: &mut [u8],
        ) -> Result<(), Error> {
            output.declassify(destination, PublicDeclassification::acknowledge())
        }

        #[inline(never)]
        pub fn output_clear(output: Output<'_, $algorithm>) {
            drop(output);
        }
    };
}

macro_rules! scalar {
    ($name:ident, $algorithm:ty) => {
        pub mod $name {
            use super::host::*;

            output_loan!($algorithm);

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

    output_loan!(Sha1);

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
    pub fn output_expose<'a>(output: &'a Md5BatchOutput<'_>, lane: usize) -> Option<&'a [u8]> {
        output.expose(lane)
    }

    #[inline(never)]
    pub fn output_declassify(
        output: Md5BatchOutput<'_>,
        destination: &mut [[u8; 16]; 8],
    ) -> Result<(), Error> {
        output.declassify(destination, PublicDeclassification::acknowledge())
    }

    #[inline(never)]
    pub fn output_clear(output: Md5BatchOutput<'_>) {
        drop(output);
    }

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
