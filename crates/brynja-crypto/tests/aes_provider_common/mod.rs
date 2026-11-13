//! Reference/mock adapters only: these tests do not exercise hardware custody.
#![forbid(unsafe_code)]

use super::{AesBackend, CIPHER, KEY_BYTES, ProviderKey, SoftwareKey};
use brynja_crypto::aes::PublicCiphertext;
use brynja_crypto::aes::provider::{Error, Permissions};
use brynja_crypto::provider::{ExternalKey, OwnedKeyBackend, ProviderFailureKind};
use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::rc::Rc;

#[path = "../aes128_provider_regressions/mod.rs"]
mod regressions;

fn must<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => resume_unwind(Box::new(format!("unexpected test failure: {error:?}"))),
    }
}

const INPUT: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

#[derive(Clone, Copy)]
enum Behavior {
    Good,
    Echo,
    AlmostEcho(usize, u8),
    Fail(ProviderFailureKind),
    Length(usize),
    Panic,
}

struct State {
    calls: Vec<(u8, bool)>,
    dropped: usize,
    destroyed: usize,
    behavior: Behavior,
    destroy_behavior: Behavior,
}

// The adapter, not the caller-facing wrapper, owns key/session identity. No free
// handle argument is accepted by operations. Bytes here are a public test key.
struct Mock {
    identity: u8,
    permissions: Permissions,
    state: Rc<RefCell<State>>,
}

impl Mock {
    fn new(permissions: Permissions) -> (Self, Rc<RefCell<State>>) {
        let state = Rc::new(RefCell::new(State {
            calls: Vec::new(),
            dropped: 0,
            destroyed: 0,
            behavior: Behavior::Good,
            destroy_behavior: Behavior::Good,
        }));
        (
            Self {
                identity: 1,
                permissions,
                state: state.clone(),
            },
            state,
        )
    }

    fn transform(
        &mut self,
        input: &[u8; 16],
        output: &mut [u8; 16],
        inverse: bool,
    ) -> Result<usize, ProviderFailureKind> {
        self.state.borrow_mut().calls.push((self.identity, inverse));
        // Deliberately write a partial result before failures or panic.
        output[..7].fill(0xee);
        match self.state.borrow().behavior {
            Behavior::Echo => {
                output.copy_from_slice(input);
                return Ok(16);
            }
            Behavior::AlmostEcho(position, mask) => {
                output.copy_from_slice(input);
                *must(output.get_mut(position).ok_or("invalid mock bit position")) ^= mask;
                return Ok(16);
            }
            Behavior::Fail(error) => return Err(error),
            Behavior::Length(length) => return Ok(length),
            Behavior::Panic => resume_unwind(Box::new("injected adapter unwind")),
            Behavior::Good => (),
        }
        let bytes: [u8; KEY_BYTES] = core::array::from_fn(|i| must(u8::try_from(i)));
        let mut storage = [0; KEY_BYTES];
        let key = must(SoftwareKey::new(&bytes, &mut storage));
        let mut temporary = [0; 16];
        let block = must(if inverse {
            key.decrypt_block(input, &mut temporary)
        } else {
            key.encrypt_block(input, &mut temporary)
        });
        output.copy_from_slice(block.expose());
        Ok(16)
    }
}

impl AesBackend for Mock {
    fn permissions(&self) -> Permissions {
        self.permissions
    }
    fn encrypt_block(
        &mut self,
        input: &[u8; 16],
        output: &mut [u8; 16],
    ) -> Result<usize, ProviderFailureKind> {
        self.transform(input, output, false)
    }
    fn decrypt_block(
        &mut self,
        input: &[u8; 16],
        output: &mut [u8; 16],
    ) -> Result<usize, ProviderFailureKind> {
        self.transform(input, output, true)
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        let mut state = self.state.borrow_mut();
        state.dropped = state.dropped.saturating_add(1);
    }
}

struct Owned(Mock);
impl AesBackend for Owned {
    fn permissions(&self) -> Permissions {
        self.0.permissions()
    }
    fn encrypt_block(
        &mut self,
        input: &[u8; 16],
        output: &mut [u8; 16],
    ) -> Result<usize, ProviderFailureKind> {
        self.0.encrypt_block(input, output)
    }
    fn decrypt_block(
        &mut self,
        input: &[u8; 16],
        output: &mut [u8; 16],
    ) -> Result<usize, ProviderFailureKind> {
        self.0.decrypt_block(input, output)
    }
}
impl OwnedKeyBackend for Owned {
    fn destroy_key(&mut self) -> Result<(), ProviderFailureKind> {
        let mut state = self.0.state.borrow_mut();
        state.destroyed = state.destroyed.saturating_add(1);
        match state.destroy_behavior {
            Behavior::Fail(error) => Err(error),
            Behavior::Panic => resume_unwind(Box::new("injected destruction unwind")),
            _ => Ok(()),
        }
    }
}

#[test]
fn reference_adapter_matches_fips_encrypt_decrypt_and_clears_outputs() {
    let (backend, state) = Mock::new(Permissions::EncryptAndDecrypt);
    let mut key = ProviderKey::new(backend);
    let mut output = [0xa5; 16];
    assert_eq!(key.permissions(), Permissions::EncryptAndDecrypt);
    for _ in 0..2 {
        let block = must(key.encrypt_block(&INPUT, &mut output));
        assert_eq!(block.expose(), CIPHER);
        drop(block);
        assert_eq!(output, [0; 16]);
        let block = must(key.decrypt_block(&CIPHER, &mut output));
        assert_eq!(block.expose(), INPUT);
        block.clear();
        assert_eq!(output, [0; 16]);
    }
    assert_eq!(
        state.borrow().calls,
        [(1, false), (1, true), (1, false), (1, true)]
    );
}

#[test]
fn public_ciphertext_commits_only_complete_success() {
    let (backend, _) = Mock::new(Permissions::Encrypt);
    let mut key = ProviderKey::new(backend);
    let mut output = [0xa5; 16];
    must(key.encrypt_block_public(&INPUT, &mut output, PublicCiphertext::acknowledge()));
    drop(key);
    assert_eq!(output, CIPHER);
}

#[test]
fn permissions_are_exact_and_rejection_does_not_dispatch_or_quarantine() {
    for permissions in [Permissions::Encrypt, Permissions::Decrypt] {
        let (backend, state) = Mock::new(permissions);
        let mut key = ProviderKey::new(backend);
        let mut output = [0xa5; 16];
        let rejected = if permissions == Permissions::Encrypt {
            key.decrypt_block(&CIPHER, &mut output)
        } else {
            key.encrypt_block(&INPUT, &mut output)
        };
        assert!(matches!(rejected, Err(Error::NotPermitted)));
        drop(rejected);
        assert_eq!(output, [0; 16]);
        assert!(state.borrow().calls.is_empty());
        if permissions == Permissions::Encrypt {
            must(key.encrypt_block(&INPUT, &mut output)).clear();
        } else {
            must(key.decrypt_block(&CIPHER, &mut output)).clear();
            output.fill(0xa5);
            assert_eq!(
                key.encrypt_block_public(&INPUT, &mut output, PublicCiphertext::acknowledge()),
                Err(Error::NotPermitted)
            );
            assert_eq!(output, [0xa5; 16]);
        }
        assert_eq!(state.borrow().calls.len(), 1);
    }
}

fn exercise_failure(behavior: Behavior, expected: Error) {
    for direction in 0..3 {
        let (backend, state) = Mock::new(Permissions::EncryptAndDecrypt);
        state.borrow_mut().behavior = behavior;
        let mut key = ProviderKey::new(backend);
        let mut output = [0xa5; 16];
        let result = catch_unwind(AssertUnwindSafe(|| match direction {
            0 => key
                .encrypt_block(&INPUT, &mut output)
                .map(|block| block.clear()),
            1 => key
                .decrypt_block(&CIPHER, &mut output)
                .map(|block| block.clear()),
            _ => key.encrypt_block_public(&INPUT, &mut output, PublicCiphertext::acknowledge()),
        }));
        if matches!(behavior, Behavior::Panic) {
            assert!(result.is_err());
        } else {
            assert_eq!(must(result), Err(expected));
        }
        assert_eq!(output, if direction == 2 { [0xa5; 16] } else { [0; 16] });
        // Even if the device recovers, this wrapper must never retry/fallback.
        state.borrow_mut().behavior = Behavior::Good;
        output.fill(0xa5);
        assert!(matches!(
            key.encrypt_block(&INPUT, &mut output),
            Err(Error::Quarantined)
        ));
        assert_eq!(output, [0; 16]);
        assert!(matches!(
            key.decrypt_block(&CIPHER, &mut output),
            Err(Error::Quarantined)
        ));
        output.fill(0xa5);
        assert_eq!(
            key.encrypt_block_public(&INPUT, &mut output, PublicCiphertext::acknowledge()),
            Err(Error::Quarantined)
        );
        assert_eq!(output, [0xa5; 16]);
        assert_eq!(state.borrow().calls.len(), 1);
    }
}

#[test]
fn every_adapter_failure_clears_or_preserves_output_and_is_terminal() {
    for error in [
        ProviderFailureKind::Unavailable,
        ProviderFailureKind::Rejected,
        ProviderFailureKind::InvalidOutput,
        ProviderFailureKind::Canceled,
        ProviderFailureKind::Failed,
    ] {
        exercise_failure(Behavior::Fail(error), Error::Provider(error));
    }
}

#[test]
fn invalid_reported_lengths_never_release_partial_output() {
    for length in [0, 1, 7, 15, 17, usize::MAX] {
        exercise_failure(
            Behavior::Length(length),
            Error::Provider(ProviderFailureKind::InvalidOutput),
        );
    }
}

#[test]
fn adapter_unwind_clears_or_preserves_output_and_is_terminal() {
    exercise_failure(Behavior::Panic, Error::Quarantined);
}

#[test]
fn separate_bindings_never_substitute_key_or_provider() {
    let (backend1, state1) = Mock::new(Permissions::Encrypt);
    let (mut backend2, state2) = Mock::new(Permissions::Decrypt);
    backend2.identity = 2;
    let mut key1 = ProviderKey::new(backend1);
    let mut key2 = ProviderKey::new(backend2);
    must(key1.encrypt_block(&INPUT, &mut [0; 16])).clear();
    must(key2.decrypt_block(&CIPHER, &mut [0; 16])).clear();
    assert_eq!(state1.borrow().calls, [(1, false)]);
    assert_eq!(state2.borrow().calls, [(2, true)]);
}

#[test]
fn dropping_borrowed_or_owned_binding_does_not_destroy_device_key() {
    let (backend, state) = Mock::new(Permissions::Encrypt);
    drop(ProviderKey::new(backend));
    assert_eq!((state.borrow().dropped, state.borrow().destroyed), (1, 0));
    let (backend, state) = Mock::new(Permissions::Encrypt);
    drop(ProviderKey::new(Owned(backend)));
    assert_eq!((state.borrow().dropped, state.borrow().destroyed), (1, 0));
}

#[test]
fn owned_destruction_is_explicit_fallible_and_never_retried() {
    for behavior in [
        Behavior::Good,
        Behavior::Fail(ProviderFailureKind::Rejected),
        Behavior::Panic,
    ] {
        let (backend, state) = Mock::new(Permissions::Encrypt);
        state.borrow_mut().destroy_behavior = behavior;
        let key = ProviderKey::new(Owned(backend));
        let result = catch_unwind(AssertUnwindSafe(|| key.destroy()));
        match behavior {
            Behavior::Good => assert_eq!(must(result), Ok(())),
            Behavior::Fail(error) => assert_eq!(must(result), Err(Error::Provider(error))),
            _ => assert!(result.is_err()),
        }
        assert_eq!((state.borrow().dropped, state.borrow().destroyed), (1, 1));
    }
}

#[test]
fn quarantined_owned_binding_can_still_explicitly_destroy() {
    let (backend, state) = Mock::new(Permissions::Encrypt);
    state.borrow_mut().behavior = Behavior::Fail(ProviderFailureKind::Unavailable);
    let mut key = ProviderKey::new(Owned(backend));
    assert!(key.encrypt_block(&INPUT, &mut [0; 16]).is_err());
    must(key.destroy());
    assert_eq!(
        (state.borrow().calls.len(), state.borrow().destroyed),
        (1, 1)
    );
}

#[test]
fn output_owner_can_outlive_provider_binding() {
    let mut output = [0; 16];
    let block = {
        let (backend, state) = Mock::new(Permissions::Encrypt);
        let mut key = ProviderKey::new(backend);
        let block = must(key.encrypt_block(&INPUT, &mut output));
        drop(key);
        assert_eq!(state.borrow().dropped, 1);
        block
    };
    assert_eq!(block.expose(), CIPHER);
    block.clear();
    assert_eq!(output, [0; 16]);
}

#[test]
fn neutral_lifecycle_does_not_require_an_aes_backend() {
    struct OtherAlgorithm<'a>(&'a mut bool);
    impl OwnedKeyBackend for OtherAlgorithm<'_> {
        fn destroy_key(&mut self) -> Result<(), ProviderFailureKind> {
            *self.0 = true;
            Ok(())
        }
    }
    let mut destroyed = false;
    must(ExternalKey::new(OtherAlgorithm(&mut destroyed)).destroy());
    assert!(destroyed);
}
