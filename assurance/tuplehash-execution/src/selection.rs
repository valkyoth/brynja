use brynja_crypto_cpu::{hardened_execution::KeccakSession, static_execution as raw};
use brynja_crypto_cpu_std::execution as hosted;
use brynja_hash_tuple::execution::Mode;
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
            Self::Portable | Self::PreferPortable => {
                eprintln!("TUPLEHASH_EXECUTION_ROUTE: Portable")
            }
            Self::Static(owner) | Self::Preferred(owner) => {
                eprintln!("TUPLEHASH_EXECUTION_ROUTE: {:?}", owner.report())
            }
            Self::Hosted(owner) => eprintln!("TUPLEHASH_EXECUTION_ROUTE: {:?}", owner.report()),
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
                "actual tuple owner route differs from selected authority",
            )),
        }
    }

    pub fn quarantine_regressions(&self) -> Result<(), io::Error> {
        use brynja_hash_tuple::{TupleHashPublicDeclassification, execution as api};
        if matches!(self, Self::Portable | Self::PreferPortable) {
            return Ok(());
        }
        let mut xof =
            api::HardenedTupleHashXof256::new(self.mode()?, b"domain").map_err(invalid)?;
        let mut reader = xof.finalize_xof().map_err(invalid)?;
        let mut fixed = api::HardenedTupleHash128::new(self.mode()?, b"domain").map_err(invalid)?;
        let mut writer = fixed.begin_item(16).map_err(invalid)?;
        writer.update(b"x").map_err(invalid)?;
        let public = api::TupleHash128::new(self.mode()?, b"domain").map_err(invalid)?;
        let stale = match self.mode()? {
            Mode::Require(s) | Mode::Prefer(s) => s,
            Mode::Portable => return Err(invalid("lost accelerated selection")),
        };
        match self {
            Self::Static(owner) | Self::Preferred(owner) => owner.quarantine(),
            Self::Hosted(owner) => owner.quarantine(),
            _ => return Err(invalid("unexpected quarantine route")),
        }
        if api::TupleHash128::new(Mode::Prefer(stale), b"domain").is_ok() {
            return Err(invalid("quarantined preference fell back"));
        }
        if writer.update(b"y").is_ok() || writer.finish().is_ok() {
            return Err(invalid("revoked item writer continued"));
        }
        let mut output = [0xa5; 32];
        if public.finalize(&mut output).is_ok() || output != [0xa5; 32] {
            return Err(invalid("quarantined public output mutation"));
        }
        if reader
            .squeeze_public(&mut output, TupleHashPublicDeclassification::acknowledge())
            .is_ok()
            || output != [0xa5; 32]
        {
            return Err(invalid("quarantined XOF public mutation"));
        }
        if reader.squeeze_secret(&mut output).is_ok() || output != [0; 32] {
            return Err(invalid("terminal XOF secret output not cleared"));
        }
        output.fill(0xa5);
        if fixed.finalize_secret(&mut output).is_ok() || output != [0; 32] {
            return Err(invalid("abandoned secret output not cleared"));
        }
        Ok(())
    }
}
