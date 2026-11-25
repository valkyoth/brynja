//! Composition tests only. No public dispatch, CPU probing override or mixed fallback.
use super::*;
use crate::{
    aes::execution,
    ghash::{self, Ghash},
};

#[derive(Default)]
struct RequiredHash {
    starts: Cell<usize>,
    reject_at: Option<usize>,
}

impl HashRoute for RequiredHash {
    fn start<'a>(
        &self,
        h: &'a Block,
        state: &'a mut Block,
        budget: u64,
    ) -> Result<Ghash<'a>, ghash::Error> {
        let n = self
            .starts
            .get()
            .checked_add(1)
            .ok_or(ghash::Error::LimitExceeded)?;
        self.starts.set(n);
        if self.reject_at == Some(n) {
            return Err(ghash::Error::Quarantined);
        }
        let hash = Ghash::new_with_backend(h, state, budget, ghash::Mode::Require)?;
        assert_eq!(hash.backend(), ghash::Backend::Pclmul);
        Ok(hash)
    }
}

struct Pair<K>(K, RequiredHash);

macro_rules! width {
    ($name:ident, $test:ident, $bytes:literal, $key:literal, $empty_tag:literal) => {
        impl Forward for Pair<execution::$name<'_, '_>> {
            fn hash_route(&self) -> &impl HashRoute {
                &self.1
            }
            fn encrypt<'a>(
                &self,
                input: &Block,
                out: &'a mut Block,
            ) -> Result<SecretBlock<'a>, Error> {
                Ok(self.0.encrypt_block(input, out)?)
            }
        }

        #[test]
        fn $test() -> Result<(), Error> {
            let authority = execution::Authority::new(execution::Kernel::X86AesNi)
                .map_err(execution::Error::from)?;
            let (mut storage, mut scalar_storage) = ([0; $bytes], [0; $bytes]);
            let raw = hex($key)?;
            let scalar = $name::new(&raw, &mut scalar_storage).map_err(Error::Aes)?;
            let native = Pair(
                execution::$name::new(&authority, &raw, &mut storage)?,
                RequiredHash::default(),
            );
            // Published empty-message answer: the 96-bit fast path hashes only the message.
            let iv = hex::<12>("cafebabefacedbaddecaf888")?;
            assert_eq!(
                seal(&native, &iv, &[], &[], &mut [], &mut [])?,
                hex($empty_tag)?
            );
            assert_eq!(native.1.starts.get(), 1);
            // Hashed IV: count both GHASH uses, for payload and for AAD-only (GMAC).
            let plain = [0x39; 17];
            for (iv, len) in [(*b"mac-case", 0), (*b"gcm-case", plain.len())] {
                let p = plain.get(..len).ok_or(Error::Invariant)?;
                let (mut a, mut b, mut tmp) = ([0; 17], [0; 17], [0; 17]);
                let a = a.get_mut(..len).ok_or(Error::Invariant)?;
                let b = b.get_mut(..len).ok_or(Error::Invariant)?;
                let work = tmp.get_mut(..len).ok_or(Error::Invariant)?;
                let expected = seal(&scalar, &iv, b"record", p, work, a)?;
                let before = native.1.starts.get();
                let tag = seal(&native, &iv, b"record", p, work, b)?;
                assert_eq!((&*b, tag), (&*a, expected));
                let mut wrong = tag;
                wrong[0] ^= 1;
                b.fill(0x55);
                assert_eq!(
                    open(&native, &iv, b"record", a, &wrong, work, b),
                    Err(Error::Authentication)
                );
                assert!(b.iter().all(|x| *x == 0x55));
                assert!(work.iter().all(|x| *x == 0));
                open(&native, &iv, b"record", a, &tag, work, b)?;
                assert_eq!(b, p);
                assert_eq!(native.1.starts.get().checked_sub(before), Some(6));
            }
            drop(native);
            assert_eq!(storage, [0; $bytes]);
            Ok(())
        }
    };
}
width!(
    Aes128ExpandedKey,
    aes128,
    176,
    "feffe9928665731c6d6a8f9467308308",
    "3247184b3c4f69a44dbcd22887bbb418"
);
width!(
    Aes192ExpandedKey,
    aes192,
    208,
    "feffe9928665731c6d6a8f9467308308feffe9928665731c",
    "c835aa88aebbc94f5a02e179fdcfc3e4"
);
width!(
    Aes256ExpandedKey,
    aes256,
    240,
    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
    "fd2caa16a5832e76aa132c1453eeda7e"
);

#[test]
fn hash_failure_at_either_stage_burns_nonce_without_commit() -> Result<(), Error> {
    let authority =
        execution::Authority::new(execution::Kernel::X86AesNi).map_err(execution::Error::from)?;
    for stage in [1, 2] {
        let mut storage = [0; 176];
        let native = Pair(
            execution::Aes128ExpandedKey::new(&authority, &[7; 16], &mut storage)?,
            RequiredHash {
                starts: Cell::new(0),
                reject_at: Some(stage),
            },
        );
        let mut key = policy::Key::<_, 16, 8>::from_reserved_invocations(native, b"test", 0, 1)?;
        let (mut data, mut scratch) = ([0x39; 17], [0xff; 17]);
        assert_eq!(
            key.seal_next(b"aad", Buffers::InPlace(&mut data), &mut scratch),
            Err(Error::Hash(ghash::Error::Quarantined))
        );
        assert_eq!(data, [0x39; 17]);
        assert_eq!(scratch, [0; 17]);
        assert_eq!(
            key.seal_next(b"aad", Buffers::InPlace(&mut data), &mut scratch),
            Err(Error::Exhausted)
        );
        drop(key);
        assert_eq!(storage, [0; 176]);
    }
    Ok(())
}
