//! Private bridge mechanics. No OS calls or host-pointer dereferences.
use super::{Error, Pending, Phase};

pub(super) fn decode(bytes: &[u8; 64]) -> [u64; 8] {
    let mut words = [0; 8];
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(8)) {
        let mut value = [0; 8];
        value.copy_from_slice(chunk);
        *word = u64::from_le_bytes(value);
    }
    words
}

pub(super) fn encode(words: [u64; 8]) -> [u8; 64] {
    let mut bytes = [0; 64];
    for (word, chunk) in words.into_iter().zip(bytes.chunks_exact_mut(8)) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

impl Pending<'_, '_, '_> {
    /// Called only by the eventual fixed native bridge immediately before entry.
    /// Addresses are integer wire fields, NOT permission to dereference them.
    /// The real bridge must retain live, exclusively owned command/staging buffers.
    pub(super) fn enter(&mut self, command: u64, destination: u64) -> Result<[u8; 1072], Error> {
        if self.phase != Phase::Prepared
            || command == 0
            || command.checked_add(64).is_none()
            || (self.exporting() && (destination == 0 || destination.checked_add(32).is_none()))
            || (!self.exporting() && destination != 0)
        {
            return self.fail();
        }
        // No admission rollback. Unknown CallEnclave outcome must quarantine.
        let Some(next) = self.session.epoch.checked_add(1) else {
            return self.fail();
        };
        self.session.epoch = next;
        self.destination = destination;
        self.phase = Phase::Entered;
        let header = encode([2, 0, self.input.0.len() as u64, command, 64, 0, 0, 0]);
        let mut request = [0; 1072];
        request[..48].copy_from_slice(&header[..48]);
        request[48..48 + self.input.0.len()].copy_from_slice(self.input.0);
        Ok(request)
    }

    /// Each offer is a copied value, never a borrowed enclave or foreign object.
    pub(super) fn offer(&mut self, bytes: &[u8; 64]) -> Result<[u8; 64], Error> {
        let words = decode(bytes);
        let token = [words[0], words[1], words[2], words[3]];
        if !matches!(self.phase, Phase::Entered | Phase::Offered)
            || token[0] | token[1] == 0
            || token[3] != 1
            || words[5..] != [0, 0, 0]
            || (!cfg!(probe_host_ignore_epoch) && token[2] != self.session.epoch)
        {
            return self.fail();
        }
        if self.phase == Phase::Entered {
            if words[4] != 0 {
                return self.fail();
            }
            if let Some(namespace) = self.session.namespace {
                if !cfg!(probe_host_ignore_identity) && namespace != token[..2] {
                    return self.fail();
                }
            } else {
                self.session.namespace = Some([token[0], token[1]]);
            }
            self.token = Some(token);
            self.phase = Phase::Offered;
        } else {
            let valid_status = if self.exporting() {
                matches!(words[4], 1 | 12)
            } else {
                words[4] == 2
            };
            if self.token != Some(token) || !valid_status {
                return self.fail();
            }
            self.first_status = words[4];
            self.phase = Phase::Replayed;
        }
        let (action, flags, destination, width) = if self.exporting() {
            (1, 0x5055_424c_4943, self.destination, 32)
        } else {
            (2, 0, 0, 0)
        };
        Ok(encode([
            token[0],
            token[1],
            token[2],
            token[3],
            action,
            flags,
            destination,
            width,
        ]))
    }

    /// Private adapter staging, PUBLIC digests only. Real OS writes remain unbound.
    pub(super) fn receive_public(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.phase != Phase::Offered || !self.exporting() || bytes.len() > 32 {
            return self.fail();
        }
        if self.received.is_some() {
            return self.fail();
        }
        self.received = Some(bytes.len());
        self.staging[..bytes.len()].copy_from_slice(bytes);
        if cfg!(probe_host_commit_early) {
            if let super::Disposition::ExportPublic(destination) = &mut self.disposition {
                destination.copy_from_slice(&self.staging);
            }
        }
        Ok(())
    }
}
