// Appended only to the isolated borrowed-host model. All transport stays private.
pub(super) trait NativeDriver {
    fn run(&mut self, pending: &mut Pending<'_, '_, '_>) -> Result<Outcome, Error>;
}

impl Session {
    pub(super) fn execute(
        &mut self,
        input: PublicInput<'_>,
        disposition: Disposition<'_>,
        driver: &mut impl NativeDriver,
    ) -> Result<Outcome, Error> {
        let mut pending = self.prepare(input, disposition)?;
        driver.run(&mut pending)
    }
}

impl<'session, 'input, 'output> Pending<'session, 'input, 'output> {
    pub(super) fn native_request(
        &mut self,
        command: u64,
        output: u64,
    ) -> Result<enclave_borrowed::Request<'input>, Error> {
        let destination = if self.exporting() { output } else { 0 };
        if self.phase != Phase::Prepared
            || (self.exporting() && (destination == 0 || destination.checked_add(32).is_none()))
        {
            return self.fail();
        }
        // Retains the original input borrow; only addresses and lengths are serialized.
        // It does NOT borrow Pending itself, so the fixed callback can update the
        // separate protocol ledger during the synchronous native call.
        let request = match enclave_borrowed::Request::new(self.input.0, command) {
            Ok(request) => request,
            Err(_) => return self.fail(),
        };
        let Some(next) = self.session.epoch.checked_add(1) else {
            return self.fail();
        };
        self.session.epoch = next;
        self.destination = destination;
        self.phase = Phase::Entered;
        Ok(request)
    }

    pub(super) fn native_exchange(
        &mut self,
        step: u64,
        offer: &[u8; 64],
        output: &[u8; 32],
    ) -> Result<[u8; 64], Error> {
        if (step == 0 && self.phase != Phase::Entered)
            || (step == 1 && self.phase != Phase::Offered)
            || step > 1
        {
            return self.fail();
        }
        if step == 1 && wire::decode(offer)[4] == 1 {
            self.receive_public(output)?;
        }
        self.offer(offer)
    }

    pub(super) fn native_finish(&mut self, ok: bool, report: [u64; 4]) -> Result<Outcome, Error> {
        if !ok {
            return self.fail();
        }
        self.finish(report[0], report[1], report[2] == 1, report[3] == 1)
    }
}
