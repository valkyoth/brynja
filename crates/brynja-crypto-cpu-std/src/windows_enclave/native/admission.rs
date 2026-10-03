use super::{Backend, Entries, Error, ImagePolicy, Protocol, pin, sys};
use std::path::Path;

impl Backend {
    pub(super) fn open_protocol(
        location: &Path,
        policy: &ImagePolicy,
        verify: impl FnOnce(&pin::Pin) -> Result<(), Error>,
        protocol: Protocol,
    ) -> Result<Self, Error> {
        if !sys::supported() {
            return Err(Error::Unsupported);
        }
        if !policy.valid() {
            return Err(Error::Image);
        }
        let pin = pin::Pin::open(location, policy)?;
        verify(&pin)?;
        let mut owner = Self {
            pin: Some(pin),
            base: 0,
            initialized: false,
            terminated: false,
            uncertain: false,
            thread: sys::thread(),
            entries: Entries::default(),
            slot: 0,
            slot_locked: false,
            live: false,
            epoch: 0,
            generation: 0,
            protocol,
        };
        owner.base = sys::create()?;
        sys::load(
            owner.base,
            &owner.pin.as_ref().ok_or(Error::Image)?.location,
        )?;
        let threads = sys::initialize(owner.base)?;
        owner.initialized = true;
        if threads != 1 {
            return Err(Error::Platform);
        }
        owner.entries = Entries {
            wire: sys::export(owner.base, b"PublicRetained\0")?,
            window: sys::export(owner.base, b"PublicLockedWindow\0")?,
            registration: sys::export(owner.base, b"PublicLockedHost\0")?,
            control: sys::export(owner.base, b"PublicRetainedControl\0")?,
            guard: sys::export(owner.base, b"PublicGuardControl\0")?,
            output: sys::export(owner.base, b"PublicRetainedOutput\0")?,
            input: sys::export(
                owner.base,
                match protocol {
                    #[cfg(feature = "strict-sha2-acceleration")]
                    Protocol::Sha512Simd => b"PublicSha512SimdInputSource\0",
                    #[cfg(feature = "strict-sha3-acceleration")]
                    Protocol::KeccakSimd => b"PublicKeccakSimdInputSource\0",
                    #[cfg(feature = "strict-sha2-acceleration")]
                    Protocol::Sha256Simd => b"PublicSha256SimdInputSource\0",
                    Protocol::Sha2 | Protocol::Sha2ShaNi => b"PublicSha2InputSource\0",
                    Protocol::Sha2Batch | Protocol::Sha2BatchShaNi => {
                        b"PublicSha2BatchInputSource\0"
                    }
                    #[cfg(feature = "strict-sha3")]
                    Protocol::Sha3 | Protocol::Sha3Avx2 => b"PublicSha3InputSource\0",
                    #[cfg(feature = "strict-sha3")]
                    Protocol::Sha3Batch | Protocol::Sha3BatchAvx2 => {
                        b"PublicSha3BatchInputSource\0"
                    }
                    #[cfg(feature = "strict-kmac")]
                    Protocol::Kmac | Protocol::KmacAvx2 => b"PublicKmacInputSource\0",
                    #[cfg(feature = "strict-tuplehash")]
                    Protocol::TupleHash | Protocol::TupleHashAvx2 => b"PublicTupleInputSource\0",
                    #[cfg(feature = "strict-sha3")]
                    Protocol::ParallelHash | Protocol::ParallelHashAvx2 => {
                        b"PublicParallelInputSource\0"
                    }
                    Protocol::Legacy => b"PublicRetainedInput\0",
                },
            )?,
            input_control: if protocol != Protocol::Legacy {
                0
            } else {
                sys::export(owner.base, b"PublicInputControl\0")?
            },
            rehash_control: if protocol != Protocol::Legacy {
                0
            } else {
                sys::export(owner.base, b"PublicRehashControl\0")?
            },
            sha2_control: match protocol {
                #[cfg(feature = "strict-sha2-acceleration")]
                Protocol::Sha512Simd => sys::export(owner.base, b"PublicSha512SimdControl\0")?,
                #[cfg(feature = "strict-sha3-acceleration")]
                Protocol::KeccakSimd => sys::export(owner.base, b"PublicKeccakSimdControl\0")?,
                #[cfg(feature = "strict-sha2-acceleration")]
                Protocol::Sha256Simd => sys::export(owner.base, b"PublicSha256SimdControl\0")?,
                Protocol::Sha2 | Protocol::Sha2ShaNi => {
                    sys::export(owner.base, b"PublicSha2Control\0")?
                }
                Protocol::Sha2Batch | Protocol::Sha2BatchShaNi => {
                    sys::export(owner.base, b"PublicSha2BatchControl\0")?
                }
                #[cfg(feature = "strict-sha3")]
                Protocol::Sha3 | Protocol::Sha3Avx2 => {
                    sys::export(owner.base, b"PublicSha3Control\0")?
                }
                #[cfg(feature = "strict-sha3")]
                Protocol::Sha3Batch | Protocol::Sha3BatchAvx2 => {
                    sys::export(owner.base, b"PublicSha3BatchControl\0")?
                }
                #[cfg(feature = "strict-kmac")]
                Protocol::Kmac | Protocol::KmacAvx2 => {
                    sys::export(owner.base, b"PublicKmacControl\0")?
                }
                #[cfg(feature = "strict-tuplehash")]
                Protocol::TupleHash | Protocol::TupleHashAvx2 => {
                    sys::export(owner.base, b"PublicTupleControl\0")?
                }
                #[cfg(feature = "strict-sha3")]
                Protocol::ParallelHash | Protocol::ParallelHashAvx2 => {
                    sys::export(owner.base, b"PublicParallelControl\0")?
                }
                Protocol::Legacy => 0,
            },
        };
        #[cfg(feature = "strict-sha2-acceleration")]
        if protocol == Protocol::Sha512Simd {
            let identity = sys::export(owner.base, b"PublicSha512SimdProtocol\0")?;
            if sys::call(identity, 0)? != super::super::sha512_simd::wire::PROTOCOL {
                return Err(Error::Unsupported);
            }
        }
        #[cfg(feature = "strict-sha2-acceleration")]
        if protocol == Protocol::Sha256Simd {
            let identity = sys::export(owner.base, b"PublicSha256SimdProtocol\0")?;
            if sys::call(identity, 0)? != super::super::sha256_simd::wire::PROTOCOL {
                return Err(Error::Unsupported);
            }
        }
        if protocol == Protocol::Sha2ShaNi {
            let identity = sys::export(owner.base, b"PublicSha2ShaNiProtocol\0")?;
            if sys::call(identity, 0)? != super::super::sha2_wire::SHA_NI_PROTOCOL {
                return Err(Error::Unsupported);
            }
        }
        #[cfg(feature = "strict-sha3")]
        if protocol == Protocol::Sha3Avx2 {
            let identity = sys::export(owner.base, b"PublicSha3Avx2Protocol\0")?;
            if sys::call(identity, 0)? != super::super::sha3_avx2_wire::PROTOCOL {
                return Err(Error::Unsupported);
            }
        }
        #[cfg(feature = "strict-sha3")]
        if protocol == Protocol::ParallelHashAvx2 {
            let identity = sys::export(owner.base, b"PublicParallelAvx2Protocol\0")?;
            if sys::call(identity, 0)? != super::super::parallel_avx2_wire::PROTOCOL {
                return Err(Error::Unsupported);
            }
        }
        if protocol == Protocol::Sha2BatchShaNi {
            let identity = sys::export(owner.base, b"PublicSha2BatchShaNiProtocol\0")?;
            if sys::call(identity, 0)? != super::super::sha2_batch_sha_ni_wire::PROTOCOL {
                return Err(Error::Unsupported);
            }
        }
        #[cfg(feature = "strict-sha3")]
        if protocol == Protocol::Sha3BatchAvx2 {
            let identity = sys::export(owner.base, b"PublicSha3BatchAvx2Protocol\0")?;
            if sys::call(identity, 0)? != super::super::sha3_batch_avx2_wire::PROTOCOL {
                return Err(Error::Unsupported);
            }
        }
        #[cfg(feature = "strict-kmac")]
        if protocol == Protocol::KmacAvx2 {
            let identity = sys::export(owner.base, b"PublicKmacAvx2Protocol\0")?;
            if sys::call(identity, 0)? != super::super::kmac_avx2_wire::PROTOCOL {
                return Err(Error::Unsupported);
            }
        }
        #[cfg(feature = "strict-tuplehash")]
        if protocol == Protocol::TupleHashAvx2 {
            let identity = sys::export(owner.base, b"PublicTupleAvx2Protocol\0")?;
            if sys::call(identity, 0)? != super::super::tuple_avx2_wire::PROTOCOL {
                return Err(Error::Unsupported);
            }
        }
        #[cfg(feature = "strict-sha3-acceleration")]
        if protocol == Protocol::KeccakSimd {
            let identity = sys::export(owner.base, b"PublicKeccakSimdProtocol\0")?;
            if sys::call(identity, 0)? != super::super::keccak_simd::wire::PROTOCOL {
                return Err(Error::Unsupported);
            }
        }
        Ok(owner)
    }
}
