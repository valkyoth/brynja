use brynja_crypto_cpu::{hardened_execution::KeccakSession, static_execution as raw};
use brynja_crypto_cpu_std::execution as hosted;
use brynja_mac_kmac::execution::Mode;
use std::io;

pub enum Selection {
    Portable,
    PreferPortable,
    Static(raw::Authority),
    Preferred(raw::Authority),
    Hosted(hosted::Authority),
}
fn invalid(error: impl core::fmt::Debug) -> io::Error {
    io::Error::other(format!("execution selection: {error:?}"))
}
impl Selection {
    pub fn new() -> Result<Self, io::Error> {
        if std::env::args().count() != 2 {
            return Err(invalid("expected exactly one execution mode"));
        }
        let mode = std::env::args()
            .nth(1)
            .ok_or_else(|| invalid("missing mode"))?;
        let kernel = if cfg!(target_arch = "x86_64") {
            raw::Kernel::X86Keccak
        } else {
            raw::Kernel::ArmKeccak
        };
        match mode.as_str() {
            "portable" => Ok(Self::Portable),
            "prefer-portable" => Ok(Self::PreferPortable),
            "static" => Ok(Self::Static(raw::Authority::new(kernel).map_err(invalid)?)),
            "prefer" => Ok(Self::Preferred(
                raw::Authority::new(kernel).map_err(invalid)?,
            )),
            "hosted" => Ok(Self::Hosted(
                hosted::Authority::new(kernel, hosted::Mode::Require).map_err(invalid)?,
            )),
            _ => Err(invalid("unknown mode")),
        }
    }
    pub fn mode(&self) -> Result<Mode<'_>, io::Error> {
        match self {
            Self::Portable => Ok(Mode::Portable),
            Self::PreferPortable => Ok(Mode::Prefer(None)),
            Self::Static(owner) => Ok(Mode::Require(Some(
                KeccakSession::from_static(owner).map_err(invalid)?,
            ))),
            Self::Preferred(owner) => Ok(Mode::Prefer(Some(
                KeccakSession::from_static(owner).map_err(invalid)?,
            ))),
            Self::Hosted(owner) => Ok(Mode::Require(Some(
                KeccakSession::from_runtime(
                    owner
                        .session()
                        .map_err(invalid)?
                        .ok_or_else(|| invalid("required hosted session absent"))?,
                )
                .map_err(invalid)?,
            ))),
        }
    }
    pub fn report(&self) {
        match self {
            Self::Portable | Self::PreferPortable => eprintln!("KMAC_EXECUTION_ROUTE: Portable"),
            Self::Static(owner) | Self::Preferred(owner) => {
                eprintln!("KMAC_EXECUTION_ROUTE: {:?}", owner.report())
            }
            Self::Hosted(owner) => eprintln!("KMAC_EXECUTION_ROUTE: {:?}", owner.report()),
        }
    }

    pub fn check_actual(&self, actual: Option<raw::Report>) -> Result<(), io::Error> {
        let expected = match self {
            Self::Portable | Self::PreferPortable => None,
            Self::Static(owner) | Self::Preferred(owner) => Some(owner.report().kernel),
            Self::Hosted(owner) => Some(owner.report().kernel),
        };
        match (expected, actual) {
            (None, None) => Ok(()),
            (Some(kernel), Some(report))
                if report.kernel == kernel && report.health == raw::Health::Healthy =>
            {
                Ok(())
            }
            _ => Err(invalid(
                "actual keyed owner route differs from selected authority",
            )),
        }
    }

    pub fn quarantine_regressions(&self) -> Result<(), io::Error> {
        use brynja_mac_kmac::{KmacPublicDeclassification, execution as api};
        if matches!(self, Self::Portable | Self::PreferPortable) {
            return Ok(());
        }
        let mut xof =
            api::KmacXof256::new(self.mode()?, &[0x42; 32], b"domain").map_err(invalid)?;
        let mut reader = xof.finalize_xof().map_err(invalid)?;
        let fixed = api::Kmac128::new(self.mode()?, &[0x42; 32], b"domain").map_err(invalid)?;
        // Capture the capability before revocation, then try preferred setup.
        let stale = match self.mode()? {
            Mode::Require(s) | Mode::Prefer(s) => s,
            Mode::Portable => return Err(invalid("lost accelerated selection")),
        };
        match self {
            Self::Static(owner) | Self::Preferred(owner) => owner.quarantine(),
            Self::Hosted(owner) => owner.quarantine(),
            _ => return Err(invalid("unexpected quarantine route")),
        }
        if api::Kmac128::new(Mode::Prefer(stale), &[0x42; 32], b"domain").is_ok() {
            return Err(invalid("quarantined preference fell back"));
        }
        let mut output = [0xa5; 32];
        if fixed.finalize_tag(&mut output).is_ok() || output != [0xa5; 32] {
            return Err(invalid("quarantined fixed tag mutation"));
        }
        if reader
            .squeeze_public(&mut output, KmacPublicDeclassification::acknowledge())
            .is_ok()
            || output != [0xa5; 32]
        {
            return Err(invalid("quarantined XOF public mutation"));
        }
        if reader.squeeze_secret(&mut output).is_ok() || output != [0; 32] {
            return Err(invalid("terminal XOF secret destination not cleared"));
        }
        Ok(())
    }
}
