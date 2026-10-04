//! Internal synchronous transport binding for the typed contract probe.
impl crate::contract::Channel for crate::adapter::Enclave {
    fn execute(
        &mut self,
        request: &crate::contract::Request<'_>,
        output: &mut [u8; 1024],
    ) -> Result<(), crate::Error> {
        // Request retains all borrows until synchronous root and worker return.
        // Fault controls do not form part of the public session interface.
        self.execute(&request.header()?, output, 0)
    }
    fn settled(&self) -> Result<(), crate::Error> {
        self.settled()
    }
}
