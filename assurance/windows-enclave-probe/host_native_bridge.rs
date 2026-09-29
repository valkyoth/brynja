// Appended only to the temporary nested model. All transport access stays private.
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

impl Pending<'_, '_, '_> {
    pub(super) fn native_request(
        &mut self,
        command: u64,
        output: u64,
    ) -> Result<[u8; 1072], Error> {
        self.enter(command, if self.exporting() { output } else { 0 })
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
