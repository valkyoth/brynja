extern crate std;

use super::{Engine, Error, Ghash};
use std::panic::{AssertUnwindSafe, catch_unwind};

pub(super) fn interrupt() -> ! {
    std::panic::resume_unwind(std::boxed::Box::new(()))
}

#[test]
fn mid_update_error_or_unwind_wipes_live_state_and_retires_owner() {
    for unwind in [false, true] {
        let (mut work, mut output) = ([0; 16], [0x53; 16]);
        let key = (1_u128 << 127).to_be_bytes();
        let mut hash = Ghash::new(&key, &mut work, 32);
        hash.engine = Engine::FailAfterOne {
            first: true,
            unwind,
        };
        assert_eq!(hash.update(&[0x35; 7]), Ok(()));
        assert_ne!(*hash.state, [0; 16]);
        assert_eq!(hash.update(&[1; 26]), Err(Error::LimitExceeded));
        let result = catch_unwind(AssertUnwindSafe(|| hash.update(&[0xa6; 25])));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(matches!(result, Ok(Err(Error::Quarantined))));
        }
        assert_eq!(*hash.state, [0; 16]); // before finish/drop
        assert_eq!((hash.used, hash.remaining), (0, 0));
        assert_eq!(hash.update(&[]), Err(Error::Quarantined));
        assert_eq!(hash.update(&[0; 16]), Err(Error::Quarantined));
        assert!(matches!(hash.finish(&mut output), Err(Error::Quarantined)));
        assert_eq!(output, [0x53; 16]);
    }
}
