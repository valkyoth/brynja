use super::{Error, State};
use core::marker::PhantomData;

/// Private implementation boundary. Never implementable by an application.
pub(super) trait Driver {
    fn begin(&mut self, input: &[u8], sequence: u64) -> Result<(), Error>;
    fn rehash(&mut self) -> Result<(), Error>;
    fn export(&mut self, public: &mut [u8; 32]) -> Result<(), Error>;
    fn cancel(&mut self) -> Result<(), Error>;
    fn close(&mut self) -> Result<(), Error>;
}
pub(super) struct Engine<D: Driver> {
    driver: D,
    sequence: u64,
    state: State,
    thread: PhantomData<*mut ()>,
}
impl<D: Driver> Engine<D> {
    pub(super) fn new(driver: D) -> Self {
        Self {
            driver,
            sequence: 0,
            state: State::Ready,
            thread: PhantomData,
        }
    }
    pub(super) fn state(&self) -> State {
        self.state
    }
    pub(super) fn abandon(&mut self) {
        self.state = State::Quarantined;
    }
    pub(super) fn begin(&mut self, input: &[u8]) -> Result<(), Error> {
        match self.state {
            State::Ready => {}
            State::Busy => return Err(Error::Busy),
            State::Closed => return Err(Error::Closed),
            State::Quarantined => return Err(Error::Quarantined),
        }
        if input.len() > 1024 {
            return Err(Error::Bounds);
        }
        self.state = State::Quarantined;
        self.sequence = self.sequence.checked_add(1).ok_or(Error::Exhausted)?;
        self.driver.begin(input, self.sequence)?;
        self.state = State::Busy;
        Ok(())
    }
    fn consume(&mut self) -> Result<(), Error> {
        if self.state != State::Busy {
            return Err(Error::Protocol);
        }
        self.state = State::Quarantined;
        Ok(())
    }
    pub(super) fn rehash(&mut self) -> Result<(), Error> {
        self.consume()?;
        self.driver.rehash()?;
        self.state = State::Busy;
        Ok(())
    }
    pub(super) fn export(&mut self, destination: &mut [u8; 32]) -> Result<(), Error> {
        self.consume()?;
        // Explicitly declassified public staging only. Never stores secrets.
        let mut public = [0; 32];
        self.driver.export(&mut public)?;
        destination.copy_from_slice(&public);
        self.state = State::Ready;
        Ok(())
    }
    pub(super) fn cancel(&mut self) -> Result<(), Error> {
        self.consume()?;
        self.driver.cancel()?;
        self.state = State::Ready;
        Ok(())
    }
    pub(super) fn close(&mut self) -> Result<(), Error> {
        if self.state == State::Closed {
            return Ok(());
        }
        self.state = State::Quarantined;
        self.driver.close()?;
        self.state = State::Closed;
        Ok(())
    }
}
impl<D: Driver> Drop for Engine<D> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct NoCalls;
    impl Driver for NoCalls {
        fn begin(&mut self, _: &[u8], _: u64) -> Result<(), Error> {
            Err(Error::Protocol)
        }
        fn rehash(&mut self) -> Result<(), Error> {
            Err(Error::Protocol)
        }
        fn export(&mut self, _: &mut [u8; 32]) -> Result<(), Error> {
            Err(Error::Protocol)
        }
        fn cancel(&mut self) -> Result<(), Error> {
            Err(Error::Protocol)
        }
        fn close(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }
    #[test]
    fn sequence_exhaustion_never_calls_driver_or_wraps() {
        let mut owner = Engine::new(NoCalls);
        owner.sequence = u64::MAX;
        assert_eq!(owner.begin(b""), Err(Error::Exhausted));
        assert_eq!(owner.sequence, u64::MAX);
        assert_eq!(owner.state(), State::Quarantined);
        assert_eq!(owner.begin(b""), Err(Error::Quarantined));
    }
}
