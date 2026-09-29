// Appended ONLY to a temporary copy of window_wire.rs under --cfg test.
// Safe in-process transport for paired Rust tests; no Windows calls are made.
pub trait HostExchange {
    fn exchange(&mut self, step: usize, offer: &[u8; 64]) -> Option<[u8; 64]>;
    fn public_output(&mut self, output: &[u8]) -> bool;
}

struct PairedTransport<'a, T: HostExchange> {
    host: &'a mut T,
    token: [u64; 4],
    input: [u8; SIZE],
    command: [u8; COMMAND],
}

impl<T: HostExchange> Transport for PairedTransport<'_, T> {
    fn identity(&mut self) -> Option<[u64; 4]> {
        Some(self.token)
    }
    fn read(&mut self, address: usize, output: &mut [u8]) -> bool {
        match (address, output.len()) {
            (1000, SIZE) => output.copy_from_slice(&self.input),
            (2000, COMMAND) => output.copy_from_slice(&self.command),
            _ => return false,
        }
        true
    }
    fn write(&mut self, address: usize, input: &[u8]) -> bool {
        match (address, input.len()) {
            (2000, COMMAND) => self.command.copy_from_slice(input),
            (3000, 32) => return self.host.public_output(input),
            _ => return false,
        }
        true
    }
    fn notify(&mut self, step: usize) -> bool {
        if let Some(command) = self.host.exchange(step, &self.command) {
            self.command = command;
            true
        } else {
            false
        }
    }
}

/// Uses the actual unchanged worker operation and owned-buffer cleanup, with
/// integer-address copies and entropy supplied by the in-process TEST adapter.
/// Reports first/replay statuses and inner cleanup; not native outer clearing.
pub fn run_pair<T: HostExchange>(
    input: [u8; 1072],
    token: [u64; 4],
    host: &mut T,
) -> (u64, u64, bool) {
    let mut transport = PairedTransport {
        host,
        input,
        token,
        command: [0; 64],
    };
    let mut workspace = Sha256Workspace::new();
    let mut buffers = Buffers {
        snapshot: [0; SIZE],
        command: [0; COMMAND],
        output: [0; 32],
    };
    let (status, _, replay) = operation(&mut workspace, &mut buffers, 1000, &mut transport);
    buffers.clear();
    let cleared = zero(&buffers.snapshot)
        && zero(&buffers.command)
        && zero(&buffers.output)
        && workspace_zero(&workspace);
    (status as u64, replay as u64, cleared)
}
