extern crate std;
use super::*;
use enclave_result::PUBLIC_OUTPUT;
use std::vec::Vec;

struct Mock {
    identity: Option<[u64; 4]>,
    input: [u8; SIZE],
    command: [u8; COMMAND],
    mode: &'static str,
    offers: usize,
    notifications: usize,
    outputs: Vec<Vec<u8>>,
}
impl Mock {
    fn new(mode: &'static str) -> Self {
        let mut result = Self {
            identity: Some([7, 8, 9, 1]),
            input: [0; SIZE],
            command: [0; COMMAND],
            mode,
            offers: 0,
            notifications: 0,
            outputs: Vec::new(),
        };
        for (value, bytes) in [2_u64, 0, 3, 2000, 64, 0]
            .iter()
            .zip(result.input.chunks_exact_mut(8))
        {
            bytes.copy_from_slice(&value.to_le_bytes());
        }
        result.input[48..51].copy_from_slice(b"abc");
        result
    }
}
impl Transport for Mock {
    fn identity(&mut self) -> Option<[u64; 4]> {
        self.identity
    }
    fn read(&mut self, address: usize, destination: &mut [u8]) -> bool {
        if address == 1000 {
            destination.copy_from_slice(&self.input);
            self.mode != "input-fail"
        } else {
            assert_eq!(address, 2000);
            destination.copy_from_slice(&self.command);
            self.mode != "command-fail"
        }
    }
    fn write(&mut self, address: usize, source: &[u8]) -> bool {
        if address == 2000 {
            self.offers += 1;
            self.command.copy_from_slice(source);
            self.mode != "offer-fail"
        } else {
            assert_eq!(address, 3000);
            self.outputs.push(if self.mode == "copy-fail" {
                source[..7].to_vec()
            } else {
                source.to_vec()
            });
            self.mode != "copy-fail"
        }
    }
    fn notify(&mut self, step: usize) -> bool {
        assert_eq!(step, self.notifications);
        self.notifications += 1;
        let mut words = wire_protocol::words::<8>(&self.command).unwrap();
        words[4..].copy_from_slice(&[1, PUBLIC_OUTPUT, 3000, 32]);
        match self.mode {
            "wrong-identity" => words[0] ^= 1,
            "wrong-identity-high" => words[1] ^= 1,
            "stale" => words[2] -= 1,
            "future" => words[2] += 1,
            "wrong-slot" => words[3] = 2,
            "no-public" => words[5] = 0,
            "bad-action" => words[4] = 3,
            "bad-width" => words[7] = 33,
            "overflow" => words[6] = u64::MAX,
            "cancel" => words[4..].copy_from_slice(&[2, 0, 0, 0]),
            "deny-first" => return false,
            "deny-second" if step == 1 => return false,
            "mutate-input" => {
                self.input.fill(0xff);
            }
            _ => (),
        }
        for (value, bytes) in words.iter().zip(self.command.chunks_exact_mut(8)) {
            bytes.copy_from_slice(&value.to_le_bytes());
        }
        true
    }
}

fn execute(io: &mut Mock) -> (usize, usize, usize) {
    let mut workspace = Sha256Workspace::new();
    let mut buffers = Buffers {
        snapshot: [0; SIZE],
        command: [0; COMMAND],
        output: [0; 32],
    };
    let result = operation(&mut workspace, &mut buffers, 1000, io);
    buffers.clear();
    assert!(
        zero(&buffers.snapshot)
            && zero(&buffers.command)
            && zero(&buffers.output)
            && workspace_zero(&workspace)
    );
    result
}

#[test]
fn public_export_then_replay_is_spent() {
    for mode in ["publish", "mutate-input"] {
        let mut io = Mock::new(mode);
        assert_eq!(execute(&mut io), (1, 3, 21));
        assert_eq!(io.outputs.len(), 1);
        assert_eq!(
            io.outputs[0],
            brynja_hash_sha2::sha256(b"abc").unwrap().as_bytes()
        );
        assert_eq!((io.offers, io.notifications), (2, 2));
    }
}
#[test]
fn foreign_stale_future_and_bad_commands_are_terminal() {
    for mode in [
        "wrong-identity",
        "wrong-identity-high",
        "stale",
        "future",
        "wrong-slot",
        "no-public",
        "bad-action",
        "bad-width",
        "overflow",
    ] {
        let mut io = Mock::new(mode);
        assert_eq!(execute(&mut io), (10, 3, 21), "{mode}");
        assert!(io.outputs.is_empty());
    }
    let mut io = Mock::new("cancel");
    assert_eq!(execute(&mut io), (2, 3, 21));
    assert!(io.outputs.is_empty());
}
#[test]
fn partial_copy_and_transport_failures_clear() {
    for (mode, result) in [
        ("input-fail", (11, 0, 0)),
        ("offer-fail", (18, 3, 0)),
        ("command-fail", (11, 3, 0)),
        ("deny-first", (13, 3, 0)),
        ("deny-second", (1, 3, 13)),
        ("copy-fail", (12, 3, 21)),
    ] {
        let mut io = Mock::new(mode);
        assert_eq!(execute(&mut io), result, "{mode}");
        if mode == "copy-fail" {
            assert_eq!(
                io.outputs,
                [brynja_hash_sha2::sha256(b"abc").unwrap().as_bytes()[..7].to_vec()]
            );
        }
    }
}
#[test]
fn invalid_identity_or_header_never_offers_result() {
    for identity in [
        None,
        Some([0, 0, 1, 1]),
        Some([1, 2, 0, 1]),
        Some([1, 2, 3, 2]),
    ] {
        let mut io = Mock::new("publish");
        io.identity = identity;
        assert_eq!(execute(&mut io), (15, 0, 0));
        assert_eq!(io.offers, 0);
    }
    for (field, value) in [
        (0, 1_u64),
        (1, 1),
        (2, 1025),
        (2, u64::MAX),
        (3, 0),
        (3, u64::MAX),
        (4, 63),
        (5, 1),
    ] {
        let mut io = Mock::new("publish");
        io.input[field * 8..field * 8 + 8].copy_from_slice(&value.to_le_bytes());
        assert_eq!(execute(&mut io), (10, 0, 0));
        assert_eq!(io.offers, 0);
    }
}
#[test]
fn all_supported_lengths_and_layout() {
    for length in 0..=1024 {
        let mut io = Mock::new("publish");
        io.input[16..24].copy_from_slice(&(length as u64).to_le_bytes());
        assert_eq!(execute(&mut io), (1, length, 21));
        assert_eq!(
            io.outputs[0],
            brynja_hash_sha2::sha256(&io.input[48..48 + length])
                .unwrap()
                .as_bytes()
        );
    }
    assert_eq!(core::mem::offset_of!(Buffers, command), SIZE);
    assert_eq!(core::mem::offset_of!(Buffers, output), SIZE + COMMAND);
    assert_eq!(core::mem::size_of::<Buffers>(), SIZE + COMMAND + 32);
    assert_eq!(core::mem::size_of::<Report>(), 64);
}

#[unsafe(no_mangle)]
extern "C" fn PublicCopyIn(_: *mut u8, _: usize, _: usize) -> i32 {
    -1
}
#[unsafe(no_mangle)]
extern "C" fn PublicCopyOut(_: usize, _: *const u8, _: usize) -> i32 {
    -1
}
#[unsafe(no_mangle)]
extern "C" fn PublicWireIdentity(_: *mut u64) -> i32 {
    0
}
#[unsafe(no_mangle)]
extern "C" fn PublicWireNotify(_: usize) -> i32 {
    0
}
