use super::*;

#[test]
fn equal_input_output_is_accepted_without_quarantine_in_every_direction() {
    // An echo mock tests the wrapper's value-independent contract; it is not
    // an AES implementation or evidence of a particular real key's fixed point.
    for input in [[0; 16], [0xff; 16], INPUT] {
        let (backend, state) = Mock::new(Permissions::EncryptAndDecrypt);
        state.borrow_mut().behavior = Behavior::Echo;
        let mut key = Aes128ProviderKey::new(Owned(backend));
        for _ in 0..2 {
            let mut output = [0xa5; 16];
            let block = must(key.encrypt_block(&input, &mut output));
            assert_eq!(block.expose(), input);
            block.clear();
            assert_eq!(output, [0; 16]);
            let block = must(key.decrypt_block(&input, &mut output));
            assert_eq!(block.expose(), input);
            drop(block);
            assert_eq!(output, [0; 16]);
            output.fill(0xa5);
            must(key.encrypt_block_public(&input, &mut output, PublicCiphertext::acknowledge()));
            assert_eq!(output, input);
        }
        assert_eq!(state.borrow().calls.len(), 6);
        must(key.destroy());
        assert_eq!(state.borrow().destroyed, 1);
    }
}

#[test]
fn successful_block_values_are_not_heuristically_validated() {
    // The trusted adapter, not the wrapper, must ensure AES correctness.
    // Single-bit differences are neither evidence of encryption nor invalid
    // block values that the wrapper can reject independently of the key.
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
fn equal_decryption_result_preserves_binding_for_later_encryption() {
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
