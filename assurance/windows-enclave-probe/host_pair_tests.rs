//! Runs the actual two Rust protocol implementations in-process, not in VBS.
use super::*;
use enclave_pair::{HostExchange, run_pair};

struct Port<'a, 's, 'i, 'o> {
    pending: &'a mut Pending<'s, 'i, 'o>,
    fail_copy: bool,
    exchanges: usize,
}

impl HostExchange for Port<'_, '_, '_, '_> {
    fn exchange(&mut self, step: usize, offer: &[u8; 64]) -> Option<[u8; 64]> {
        assert_eq!(step, self.exchanges);
        self.exchanges += 1;
        self.pending.offer(offer).ok()
    }
    fn public_output(&mut self, bytes: &[u8]) -> bool {
        if self.fail_copy {
            self.pending.receive_public(&bytes[..7]).unwrap();
            false
        } else {
            self.pending.receive_public(bytes).unwrap();
            true
        }
    }
}

fn paired(input: &[u8], expected: &[u8; 32]) {
    let mut session = Session::new();
    for mode in 0..3 {
        let mut output = [0xa5; 32];
        let disposition = if mode == 1 {
            Disposition::Cancel
        } else {
            Disposition::ExportPublic(&mut output)
        };
        let mut pending = session
            .prepare(PublicInput::acknowledge(input), disposition)
            .unwrap();
        let request = pending
            .enter(2000, if mode == 1 { 0 } else { 3000 })
            .unwrap();
        let epoch = pending.session.epoch;
        let mut port = Port {
            pending: &mut pending,
            fail_copy: mode == 2,
            exchanges: 0,
        };
        let (first, second, inner_clear) = run_pair(request, [7, 8, epoch, 1], &mut port);
        assert_eq!(port.exchanges, 2);
        assert_eq!(
            (first, second, inner_clear),
            (
                match mode {
                    0 => 1,
                    1 => 2,
                    _ => 12,
                },
                21,
                true
            )
        );
        assert_eq!(
            pending.finish(first, second, inner_clear, true),
            match mode {
                0 => Ok(Outcome::Exported),
                1 => Ok(Outcome::Cancelled),
                _ => Err(Error::Copy),
            }
        );
        drop(pending);
        assert_eq!(session.state(), State::Ready);
        assert_eq!(output, if mode == 0 { *expected } else { [0xa5; 32] });
    }
}

#[test]
fn actual_worker_requires_host_outer_cleanup_confirmation() {
    let mut session = Session::new();
    let mut output = [0xa5; 32];
    let mut pending = session
        .prepare(
            PublicInput::acknowledge(b"abc"),
            Disposition::ExportPublic(&mut output),
        )
        .unwrap();
    let request = pending.enter(2000, 3000).unwrap();
    let (first, second, inner) = run_pair(
        request,
        [7, 8, 1, 1],
        &mut Port {
            pending: &mut pending,
            fail_copy: false,
            exchanges: 0,
        },
    );
    assert_eq!((first, second, inner), (1, 21, true));
    assert_eq!(
        pending.finish(first, second, inner, false),
        Err(Error::Protocol)
    );
    drop(pending);
    assert_eq!(session.state(), State::Quarantined);
    assert_eq!(output, [0xa5; 32]);
}

// The independent Python hashlib campaign is generated into this private module.
