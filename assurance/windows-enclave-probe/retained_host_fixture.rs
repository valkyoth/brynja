//! Synthetic downstream compile-test adapter. NEVER linked by a native build.
use super::{
    NonZeroU64, Session,
    transport::{Driver, Outcome, Receipt},
};
pub struct TestDriver;
impl TestDriver {
    fn receipt(generation: u64, outcome: Outcome) -> Result<Receipt, ()> {
        Ok(Receipt {
            identity: 7,
            generation,
            outcome,
            worker_clear: true,
            result_clear: outcome != Outcome::Ready,
            deleted: outcome == Outcome::Released,
        })
    }
}
impl Driver for TestDriver {
    fn begin(&mut self, _: u8, generation: u64) -> Result<Receipt, ()> {
        Self::receipt(generation, Outcome::Ready)
    }
    fn export(&mut self, generation: u64, staging: &mut [u8; 32]) -> Result<Receipt, ()> {
        staging.fill(0x5a);
        Self::receipt(generation, Outcome::Exported)
    }
    fn cancel(&mut self, generation: u64) -> Result<Receipt, ()> {
        Self::receipt(generation, Outcome::Cancelled)
    }
    fn release(&mut self, generation: u64) -> Result<Receipt, ()> {
        Self::receipt(generation, Outcome::Released)
    }
}
pub fn fixture() -> Session<TestDriver> {
    Session::from_driver(
        TestDriver,
        NonZeroU64::new(7).expect("nonzero test constant"),
    )
}
