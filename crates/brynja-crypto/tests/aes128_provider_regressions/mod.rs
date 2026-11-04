use super::*;

#[test]
fn echoed_encryption_is_atomic_and_permanently_quarantines() {
    for input in [[0; 16], [0xff; 16], INPUT] {
        for public in [false, true] {
            let (backend, state) = Mock::new(Permissions::EncryptAndDecrypt);
            state.borrow_mut().behavior = Behavior::Echo;
            let mut key = Aes128ProviderKey::new(Owned(backend));
            let mut output = [0xa5; 16];
            let result = if public {
                key.encrypt_block_public(&input, &mut output, PublicCiphertext::acknowledge())
            } else {
                key.encrypt_block(&input, &mut output)
                    .map(|block| block.clear())
            };
            assert_eq!(
                result,
                Err(Error::Provider(ProviderFailureKind::InvalidOutput))
            );
            assert_eq!(output, if public { [0xa5; 16] } else { [0; 16] });
            state.borrow_mut().behavior = Behavior::Good;
            assert!(matches!(
                key.encrypt_block(&INPUT, &mut output),
                Err(Error::Quarantined)
            ));
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
            must(key.destroy());
            assert_eq!(state.borrow().destroyed, 1);
        }
    }
}

#[test]
fn echo_guard_checks_every_bit_but_does_not_validate_encryption() {
    // Deliberately incorrect output differing in any single bit passes this
    // narrow policy. It is not an AES correctness check or leakage detector.
    let (backend, state) = Mock::new(Permissions::Encrypt);
    let mut key = Aes128ProviderKey::new(backend);
    for position in 0..16 {
        for bit in 0..8 {
            let mask = 1 << bit;
            state.borrow_mut().behavior = Behavior::AlmostEcho(position, mask);
            let mut expected = INPUT;
            *must(
                expected
                    .get_mut(position)
                    .ok_or("invalid test bit position"),
            ) ^= mask;
            let mut output = [0xa5; 16];
            let block = must(key.encrypt_block(&INPUT, &mut output));
            assert_eq!(block.expose(), expected);
            block.clear();
            assert_eq!(output, [0; 16]);
            must(key.encrypt_block_public(&INPUT, &mut output, PublicCiphertext::acknowledge()));
            assert_eq!(output, expected);
        }
    }
    assert_eq!(state.borrow().calls.len(), 256);
}

#[test]
fn echo_policy_does_not_reject_decryption_fixed_points() {
    let (backend, state) = Mock::new(Permissions::EncryptAndDecrypt);
    state.borrow_mut().behavior = Behavior::Echo;
    let mut key = Aes128ProviderKey::new(backend);
    let mut output = [0xa5; 16];
    let block = must(key.decrypt_block(&INPUT, &mut output));
    assert_eq!(block.expose(), INPUT);
    block.clear();
    assert_eq!(output, [0; 16]);
    state.borrow_mut().behavior = Behavior::Good;
    must(key.encrypt_block_public(&INPUT, &mut output, PublicCiphertext::acknowledge()));
    assert_eq!(output, CIPHER);
}

// Send but not Sync: a binding may move to a worker without sharing its session.
struct WorkerBackend(std::cell::Cell<usize>);
impl Aes128Backend for WorkerBackend {
    fn permissions(&self) -> Permissions {
        Permissions::EncryptAndDecrypt
    }
    fn encrypt_block(
        &mut self,
        input: &[u8; 16],
        output: &mut [u8; 16],
    ) -> Result<usize, ProviderFailureKind> {
        assert_eq!(input, &INPUT);
        self.0.set(self.0.get().saturating_add(1));
        output.copy_from_slice(&CIPHER);
        Ok(16)
    }
    fn decrypt_block(
        &mut self,
        input: &[u8; 16],
        output: &mut [u8; 16],
    ) -> Result<usize, ProviderFailureKind> {
        assert_eq!(input, &CIPHER);
        self.0.set(self.0.get().saturating_add(1));
        output.copy_from_slice(&INPUT);
        Ok(16)
    }
}
impl OwnedKeyBackend for WorkerBackend {
    fn destroy_key(&mut self) -> Result<(), ProviderFailureKind> {
        assert_eq!(self.0.get(), 2);
        Ok(())
    }
}

#[test]
fn send_backend_binding_moves_to_worker_and_returns_for_destruction() {
    let key = Aes128ProviderKey::new(WorkerBackend(std::cell::Cell::new(0)));
    let key = must(
        std::thread::spawn(move || {
            let mut key = key;
            let mut output = [0; 16];
            must(key.encrypt_block_public(&INPUT, &mut output, PublicCiphertext::acknowledge()));
            assert_eq!(output, CIPHER);
            let block = must(key.decrypt_block(&CIPHER, &mut output));
            assert_eq!(block.expose(), INPUT);
            block.clear();
            assert_eq!(output, [0; 16]);
            key
        })
        .join(),
    );
    must(key.destroy());
    let neutral = ExternalKey::new(());
    must(std::thread::spawn(move || drop(neutral)).join());
}
