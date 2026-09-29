extern crate std;
use super::*;
use std::vec::Vec;

struct Mock {
    wire: [u8; SIZE],
    read_ok: bool,
    hook_ok: bool,
    write_ok: bool,
    mutate: bool,
    reads: usize,
    writes: usize,
    sent: Vec<u8>,
}
impl Mock {
    fn new() -> Self {
        let mut this = Self {
            wire: [0; SIZE],
            read_ok: true,
            hook_ok: true,
            write_ok: true,
            mutate: false,
            reads: 0,
            writes: 0,
            sent: Vec::new(),
        };
        for (index, word) in [1_u64, 1, 3, 0x10000, 32, PUBLIC].iter().enumerate() {
            this.word(index, *word);
        }
        this.wire[48..51].copy_from_slice(b"abc");
        this
    }
    fn word(&mut self, index: usize, word: u64) {
        self.wire[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
}
impl Transport for Mock {
    fn read(&mut self, out: &mut [u8; SIZE]) -> bool {
        self.reads += 1;
        out.copy_from_slice(&self.wire); // failure may have partially written
        self.read_ok
    }
    fn copied(&mut self) -> bool {
        if self.mutate {
            self.wire[48..51].copy_from_slice(b"xyz");
        }
        self.hook_ok
    }
    fn write(&mut self, destination: usize, input: &[u8; 32]) -> bool {
        assert_eq!(destination, 0x10000);
        self.writes += 1;
        self.sent
            .extend_from_slice(if self.write_ok { input } else { &input[..16] });
        self.write_ok
    }
}

fn execute(io: &mut Mock) -> (usize, usize, usize) {
    let mut workspace = Sha256Workspace::new();
    let mut buffers = Buffers {
        snapshot: [0; SIZE],
        output: [0; 32],
    };
    let value = operation(&mut workspace, &mut buffers, io);
    buffers.clear();
    assert!(zero(&buffers.snapshot) && zero(&buffers.output) && workspace_zero(&workspace));
    value
}

#[test]
fn public_result_matches_and_snapshot_is_not_reread() {
    for mutate in [false, true] {
        let mut io = Mock::new();
        io.mutate = mutate;
        assert_eq!(execute(&mut io), (1, 3, 32));
        assert_eq!(io.reads, 1);
        assert_eq!(io.writes, 1);
        assert_eq!(
            io.sent.as_slice(),
            brynja_hash_sha2::sha256(b"abc").unwrap().as_bytes()
        );
    }
}
#[test]
fn invalid_headers_never_export() {
    for (index, word) in [
        (0, 0),
        (0, 2),
        (1, 0),
        (1, 3),
        (2, 1025),
        (2, u64::MAX),
        (3, 0),
        (3, u64::MAX),
        (4, 0),
        (4, 31),
        (4, 33),
        (5, 0),
        (5, PUBLIC + 1),
    ] {
        let mut io = Mock::new();
        io.word(index, word);
        assert_eq!(execute(&mut io), (10, 0, 0), "field={index}, word={word}");
        assert_eq!(io.writes, 0);
    }
}
#[test]
fn discard_retains_no_host_output() {
    let mut io = Mock::new();
    for (index, word) in [(1, 2), (3, 0), (4, 0), (5, 0)] {
        io.word(index, word);
    }
    assert_eq!(execute(&mut io), (2, 3, 0));
    assert_eq!(io.writes, 0);
    for (index, word) in [(3, 1), (4, 32), (5, PUBLIC)] {
        let mut broken = Mock::new();
        broken.wire.copy_from_slice(&io.wire);
        broken.word(index, word);
        assert_eq!(execute(&mut broken), (10, 0, 0));
    }
}
#[test]
fn copy_and_hook_failures_clear_local_storage() {
    let mut io = Mock::new();
    io.read_ok = false;
    assert_eq!(execute(&mut io), (11, 0, 0));
    assert_eq!(io.writes, 0);
    let mut io = Mock::new();
    io.hook_ok = false;
    assert_eq!(execute(&mut io), (13, 0, 0));
    assert_eq!(io.writes, 0);
    let mut io = Mock::new();
    io.write_ok = false;
    assert_eq!(execute(&mut io), (12, 3, 0));
    assert_eq!(io.sent.len(), 16); // No false claim of atomic host copy-out.
}
#[test]
fn every_allowed_length_and_geometry() {
    for length in 0..=1024 {
        let mut io = Mock::new();
        io.word(2, length);
        assert_eq!(execute(&mut io), (1, length as usize, 32));
        assert_eq!(
            io.sent.as_slice(),
            brynja_hash_sha2::sha256(&io.wire[48..48 + length as usize])
                .unwrap()
                .as_bytes()
        );
    }
    assert_eq!(core::mem::size_of::<Report>(), 64);
    assert_eq!(core::mem::offset_of!(Report, owner_size), 56);
    assert!(within(10, 20, 10, 30));
    assert!(!within(10, 21, 10, 30));
    assert!(!within(usize::MAX, 1, 0, usize::MAX));
}

// Unused native adapter symbols for local unit-test linking. Test transport is
// the safe Mock above, not fake native enclave evidence.
#[unsafe(no_mangle)]
extern "C" fn PublicCopyIn(_: *mut u8, _: usize, _: usize) -> i32 {
    -1
}
#[unsafe(no_mangle)]
extern "C" fn PublicCopyOut(_: usize, _: *const u8, _: usize) -> i32 {
    -1
}
#[unsafe(no_mangle)]
extern "C" fn PublicSnapshotReady() -> i32 {
    0
}
