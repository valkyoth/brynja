//! Explicit architecture-specific ChaCha20 and Poly1305 execution. The host must keep
//! the advertised ISA usable while the handle is live. No CPU pinning or
//! automatic fallback. Short inputs may run entirely as scalar operations.
use crate::{Buffers, Error, Opener, Sealer};
#[cfg(target_arch = "aarch64")]
use brynja_cipher_chacha::ChaCha20Neon as NativeStream;
#[cfg(target_arch = "x86_64")]
use brynja_cipher_chacha::ChaCha20Sse2 as NativeStream;
#[cfg(target_arch = "x86_64")]
pub use brynja_mac_poly1305::execution::AdmissionError;
#[cfg(target_arch = "x86_64")]
pub(super) use brynja_mac_poly1305::execution::{Avx2 as MacCpu, Poly1305Avx2 as NativeMac};
#[cfg(target_arch = "aarch64")]
pub use brynja_mac_poly1305::neon::AdmissionError;
#[cfg(target_arch = "aarch64")]
pub(super) use brynja_mac_poly1305::neon::{Neon as MacCpu, Poly1305Neon as NativeMac};

pub(super) fn start_mac<'k, 'p>(
    one: brynja_mac_poly1305::OneTimeKey<'k>,
    cpu: &'p mut MacCpu,
) -> Result<NativeMac<'k, 'p>, Error> {
    #[cfg(target_arch = "x86_64")]
    let result = one.start_avx2(cpu);
    #[cfg(target_arch = "aarch64")]
    let result = one.start_neon(cpu);
    result.map_err(|_| Error::Invariant)
}

/// Required-native, thread-local capability. Contains no application key.
pub struct Pair {
    mac: MacCpu,
    healthy: bool,
}
/// Linux x86-64 SSE2/AVX2 pair.
#[cfg(target_arch = "x86_64")]
pub use Pair as X86Pair;
/// Little-endian Linux or macOS AArch64 pair. The target must provide NEON.
#[cfg(target_arch = "aarch64")]
pub use Pair as ArmPair;

// Public zero-key / zero-nonce keystream for counters 0..=3 in wire order.
// The first group in the native owner runs all four lanes, unlike counter-zero
// one-time-key derivation, which needs only 32 bytes and stays scalar.
const STREAM_KAT: [u64; 32] = [
    0x76b8e0ada0f13d90,
    0x405d6ae55386bd28,
    0xbdd219b8a08ded1a,
    0xa836efcc8b770dc7,
    0xda41597c5157488d,
    0x7724e03fb8d84a37,
    0x6a43b8f41518a11c,
    0xc387b669b2ee6586,
    0x9f07e7be5551387a,
    0x98ba977c732d080d,
    0xcb0f29a048e36569,
    0x12c6533e32ee7aed,
    0x29b721769ce64e43,
    0xd57133b074d839d5,
    0x31ed1f28510afb45,
    0xace10a1f4b794d6f,
    0x2d09a0e663266ce1,
    0xae7ed1081968a075,
    0x8e718e997bd362c6,
    0xb0c34634a9a0b35d,
    0x012737681f7b5d0f,
    0x281e3afde458bc1e,
    0x73d2d313c9cf94c0,
    0x5ff3716240a248f2,
    0x1320a058d7b3566b,
    0xd520daaa3ed2bf0a,
    0xc5b8b120fb852773,
    0xc3639734b45c91a4,
    0x2dd4cb83f8840d2e,
    0xedb158131062ac3f,
    0x1f2cf8ff6dcd1856,
    0xe86a1e6c3167167e,
];

impl Pair {
    /// Require passing Poly1305 and four-block ChaCha20 startup tests. On ARM,
    /// NEON is a build-target requirement, not dynamically discovered.
    pub fn probe() -> Result<Self, AdmissionError> {
        let mac = MacCpu::probe()?;
        let mut bytes = [0; 256];
        NativeStream::new(core::hint::black_box(&[0; 32]), [0; 12], 0)
            .apply_keystream_in_place(&mut bytes)
            .map_err(|_| AdmissionError::Quarantined)?;
        if !bytes
            .as_chunks::<8>()
            .0
            .iter()
            .zip(STREAM_KAT)
            .all(|(actual, want)| u64::from_be_bytes(*actual) == want)
        {
            return Err(AdmissionError::Quarantined);
        }
        Ok(Self { mac, healthy: true })
    }

    fn check(&self) -> Result<(), Error> {
        if !self.healthy {
            return Err(Error::Invariant);
        }
        self.mac.check().map_err(|_| Error::Invariant)
    }

    // Mark terminal before keyed work. A bad peer tag is expected input,
    // not a primitive failure. An unwind or internal error retires the pair.
    fn run<T>(&mut self, work: impl FnOnce(&mut MacCpu) -> Result<T, Error>) -> Result<T, Error> {
        self.check()?;
        self.healthy = false;
        let result = work(&mut self.mac);
        self.healthy = matches!(result, Ok(_) | Err(Error::Authentication));
        result
    }
}

/// Borrowed paired sender. It uses the original sender's nonce allocation,
/// so switching between portable and paired calls cannot rewind the counter.
pub struct PairedSealer<'p, 'k> {
    pair: &'p mut Pair,
    sender: &'p mut Sealer<'k>,
}

impl<'k> Sealer<'k> {
    /// Use an admitted pair with this sender's existing reservation.
    pub fn with_pair<'p>(&'p mut self, pair: &'p mut Pair) -> Result<PairedSealer<'p, 'k>, Error> {
        pair.check()?;
        Ok(PairedSealer { pair, sender: self })
    }
}

impl PairedSealer<'_, '_> {
    /// Seal into disjoint output, committing only on success.
    pub fn seal(
        &mut self,
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<([u8; 12], [u8; 16]), Error> {
        self.send(aad, Buffers::Separate(input, output), scratch)
    }
    /// Replace plaintext only after ciphertext and the full tag are ready.
    pub fn seal_in_place(
        &mut self,
        aad: &[u8],
        data: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<([u8; 12], [u8; 16]), Error> {
        self.send(aad, Buffers::InPlace(data), scratch)
    }
    fn send(
        &mut self,
        aad: &[u8],
        io: Buffers<'_>,
        scratch: &mut [u8],
    ) -> Result<([u8; 12], [u8; 16]), Error> {
        self.pair.check()?;
        let frame = io.admit(aad, scratch)?;
        let nonce = self.sender.take_nonce()?;
        let key = self.sender.key;
        self.pair.run(|cpu| {
            io.transact(scratch, |input, work| {
                crypt(key, nonce, input, work)?;
                let tag = frame.with_paired_mac(key, nonce, aad, work, cpu, |mac| {
                    mac.finalize().map_err(|_| Error::Invariant)
                })?;
                Ok((nonce, tag))
            })
        })
    }
}

/// Receive-only binding to a tested pair. Does not enforce replay policy.
pub struct PairedOpener<'p, 'k> {
    pair: &'p mut Pair,
    key: &'k [u8; 32],
}

impl<'k> Opener<'k> {
    /// Authenticate and open with this key and the explicitly supplied pair.
    pub fn with_pair<'p>(&self, pair: &'p mut Pair) -> Result<PairedOpener<'p, 'k>, Error> {
        pair.check()?;
        Ok(PairedOpener { pair, key: self.0 })
    }
}

impl PairedOpener<'_, '_> {
    /// Open into disjoint output only after full-tag verification.
    pub fn open(
        &mut self,
        nonce: [u8; 12],
        aad: &[u8],
        tag: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<(), Error> {
        self.receive(nonce, aad, tag, Buffers::Separate(input, output), scratch)
    }
    /// Open in place. A rejected tag leaves ciphertext unchanged.
    pub fn open_in_place(
        &mut self,
        nonce: [u8; 12],
        aad: &[u8],
        tag: &[u8; 16],
        data: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<(), Error> {
        self.receive(nonce, aad, tag, Buffers::InPlace(data), scratch)
    }
    fn receive(
        &mut self,
        nonce: [u8; 12],
        aad: &[u8],
        tag: &[u8; 16],
        io: Buffers<'_>,
        scratch: &mut [u8],
    ) -> Result<(), Error> {
        self.pair.check()?;
        let frame = io.admit(aad, scratch)?;
        self.pair.run(|cpu| {
            io.transact(scratch, |input, work| {
                frame.with_paired_mac(self.key, nonce, aad, input, cpu, |mac| {
                    mac.verify(tag).map_err(|err| match err {
                        brynja_mac_poly1305::Error::Authentication => Error::Authentication,
                        _ => Error::Invariant,
                    })
                })?;
                crypt(self.key, nonce, input, work)
            })
        })
    }
}

fn crypt(key: &[u8; 32], nonce: [u8; 12], input: &[u8], work: &mut [u8]) -> Result<(), Error> {
    #[cfg(test)]
    crate::interruptions::Stage::BeforePayload.check()?;
    NativeStream::new(key, nonce, 1)
        .apply_keystream(input, work)
        .map_err(|_| Error::Invariant)?;
    #[cfg(test)]
    crate::interruptions::Stage::AfterPayload.check()?;
    Ok(())
}
