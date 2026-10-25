//! Explicit route selection for synthetic inputs only; no production facade.
use brynja_legacy_hmac::{Algorithm, BitString, Hmac, LegacyUse, Md5, Sha1, execution, md5_batch};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use brynja_legacy_hmac_std::macos_resident as host;
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
use brynja_legacy_hmac_std::strict_execution as host;
use std::hint::black_box;
pub type Result<T> = std::result::Result<T, String>;
pub type Tags = [[u8; 20]; 8];
pub fn checked<T>(value: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    value.map_err(|error| format!("{error:?}"))
}
pub fn messages() -> [[u8; 73]; 8] {
    core::array::from_fn(|lane| [0x37 ^ lane as u8; 73])
}
pub fn reference<A: Algorithm>(key: &[u8], bytes: usize, lanes: usize) -> Result<Tags> {
    let mut tags = [[0; 20]; 8];
    for (output, message) in tags.iter_mut().zip(messages()).take(lanes) {
        let mut state = checked(Hmac::<A>::with_tag_length(
            LegacyUse::acknowledge(),
            key,
            bytes,
        ))?;
        checked(state.update(&message))?;
        let _ = checked(state.finalize_tag(&mut output[..bytes]))?;
    }
    Ok(tags)
}
pub enum Route {
    PortableSha1,
    PortableMd5,
    StaticSha1(execution::Sha1Executor),
    StaticMd5(md5_batch::Md5Executor),
    HostedSha1(host::Session<Sha1>),
    HostedMd5(host::Session<Md5>),
    CompiledSha1(host::Sha1CompiledSession),
    CompiledMd5(host::Md5BatchSession),
}
impl Route {
    pub fn new(route: &str, family: &str, bytes: usize) -> Result<Self> {
        let ack = LegacyUse::acknowledge();
        let limits = host::Limits {
            stack_bytes: 262144,
            max_stack_mapping_bytes: 1048576,
            max_buffer_mapping_bytes: 65536,
            max_key_bytes: 200,
            max_message_bits: 1024,
            max_chunks: 1,
        };
        let policy = host::TagPolicy::Bytes(bytes);
        if route.starts_with("linux-") && !cfg!(all(target_os = "linux", target_env = "gnu")) {
            return Err("Linux route requires native GNU/Linux".into());
        }
        if route.starts_with("macos-") && !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            return Err("resident route requires native Apple Silicon".into());
        }
        match (route, family) {
            ("portable", "sha1") => Ok(Self::PortableSha1),
            ("portable", "md5") => Ok(Self::PortableMd5),
            ("static", "sha1") => {
                let owner = checked(execution::Sha1Executor::for_compiled_target(
                    execution::Sha1Mode::Require,
                ))?;
                owner
                    .report()
                    .backend
                    .ok_or("required SHA-1 authority absent")?;
                Ok(Self::StaticSha1(owner))
            }
            ("static", "md5") => {
                let owner = checked(md5_batch::Md5Executor::for_compiled_target(
                    md5_batch::Md5Mode::Require,
                ))?;
                owner.backend().ok_or("required MD5 authority absent")?;
                Ok(Self::StaticMd5(owner))
            }
            ("linux-protected" | "macos-resident", "sha1") => Ok(Self::HostedSha1(checked(
                host::Session::new(ack, policy, limits),
            )?)),
            ("linux-protected" | "macos-resident", "md5") => Ok(Self::HostedMd5(checked(
                host::Session::new(ack, policy, limits),
            )?)),
            ("linux-compiled" | "macos-compiled", "sha1") => Ok(Self::CompiledSha1(checked(
                host::Sha1CompiledSession::new(ack, policy, limits),
            )?)),
            ("linux-compiled" | "macos-compiled", "md5") => {
                Ok(Self::CompiledMd5(checked(host::Md5BatchSession::new(
                    ack,
                    policy,
                    host::Md5BatchLimits {
                        stack_bytes: limits.stack_bytes,
                        max_stack_mapping_bytes: limits.max_stack_mapping_bytes,
                        max_buffer_mapping_bytes: limits.max_buffer_mapping_bytes,
                        max_key_bytes: 200,
                        max_message_bits: 1024,
                        max_compressions: 128,
                    },
                ))?))
            }
            _ => Err("unsupported explicit legacy route/family".into()),
        }
    }
    pub fn lanes(&self) -> usize {
        match self {
            Self::StaticMd5(owner) => owner.backend().map_or(0, |backend| backend.lane_width()),
            Self::CompiledMd5(owner) => owner.vector_width(),
            _ => 1,
        }
    }
    pub fn operation(
        &mut self,
        key: &[u8],
        candidate: Option<&Tags>,
        out: &mut Tags,
        bytes: usize,
    ) -> Result<bool> {
        let key = black_box(key);
        let messages = messages();
        let message = black_box(&messages[0][..]);
        let lanes = self.lanes();
        match self {
            Self::PortableSha1 => portable::<Sha1>(key, message, candidate, out, bytes),
            Self::PortableMd5 => portable::<Md5>(key, message, candidate, out, bytes),
            Self::StaticSha1(owner) => {
                let mut state = checked(execution::Sha1Hmac::with_tag_length(
                    LegacyUse::acknowledge(),
                    owner,
                    key,
                    bytes,
                ))?;
                checked(state.update(message))?;
                if let Some(candidate) = candidate {
                    return Ok(
                        checked(state.verify(black_box(&candidate[0][..bytes])))?.expose_public()
                    );
                }
                black_box(checked(state.finalize_tag(&mut out[0][..bytes]))?.as_bytes());
                Ok(false)
            }
            Self::StaticMd5(owner) => {
                let mut inputs = [const { None }; 8];
                for (input, message) in inputs.iter_mut().zip(&messages).take(lanes) {
                    *input = Some(md5_batch::Input::new(
                        key,
                        checked(BitString::new(message, 8))?,
                    ));
                }
                let selection = checked(md5_batch::Md5Batch::with_tag_length(
                    LegacyUse::acknowledge(),
                    owner,
                    bytes,
                ))?;
                let mut control = md5_batch::Md5BatchControl::new(128);
                if let Some(candidate) = candidate {
                    let candidates = core::array::from_fn(|lane| {
                        (lane < lanes).then_some(&candidate[lane][..bytes])
                    });
                    let (decision, report) =
                        checked(selection.verify(&inputs, black_box(&candidates), &mut control))?;
                    actual_md5(report, lanes)?;
                    return Ok(decision.expose_public());
                }
                let mut rows = [[0; 16]; 8];
                let (tags, report) =
                    checked(selection.authenticate_secret(&inputs, &mut rows, &mut control))?;
                actual_md5(report, lanes)?;
                for (lane, output) in out.iter_mut().enumerate().take(lanes) {
                    output[..bytes]
                        .copy_from_slice(black_box(tags.expose(lane).ok_or("missing MD5 output")?));
                }
                Ok(false)
            }
            Self::HostedSha1(session) => hosted(session, key, message, candidate, out, bytes),
            Self::HostedMd5(session) => hosted(session, key, message, candidate, out, bytes),
            Self::CompiledSha1(session) => {
                if let Some(candidate) = candidate {
                    return authentication(session.verify(
                        host::Request {
                            key,
                            chunks: &[message],
                            tail: host::Bits::empty(),
                        },
                        black_box(&candidate[0][..bytes]),
                        &host::Cancellation::new(),
                    ));
                }
                let tag = checked(session.authenticate(key, message))?;
                out[0][..bytes].copy_from_slice(black_box(tag.expose()));
                Ok(false)
            }
            Self::CompiledMd5(session) => {
                let inputs = core::array::from_fn(|lane| {
                    (lane < lanes).then_some(host::Md5BatchInput {
                        key,
                        message: host::Bits::bytes(&messages[lane]),
                    })
                });
                if let Some(candidate) = candidate {
                    let candidates = core::array::from_fn(|lane| {
                        (lane < lanes).then_some(&candidate[lane][..bytes])
                    });
                    return authentication(session.verify(
                        &inputs,
                        black_box(&candidates),
                        &host::Cancellation::new(),
                    ));
                }
                let tags = checked(session.compute(&inputs, &host::Cancellation::new()))?;
                for (lane, output) in out.iter_mut().enumerate().take(lanes) {
                    output[..bytes].copy_from_slice(black_box(
                        tags.expose(lane).ok_or("missing hosted MD5 output")?,
                    ));
                }
                Ok(false)
            }
        }
    }
}
fn portable<A: Algorithm>(
    key: &[u8],
    message: &[u8],
    candidate: Option<&Tags>,
    out: &mut Tags,
    bytes: usize,
) -> Result<bool> {
    let mut state = checked(Hmac::<A>::with_tag_length(
        LegacyUse::acknowledge(),
        key,
        bytes,
    ))?;
    checked(state.update(message))?;
    if let Some(candidate) = candidate {
        return Ok(checked(state.verify(black_box(&candidate[0][..bytes])))?.expose_public());
    }
    black_box(checked(state.finalize_tag(&mut out[0][..bytes]))?.as_bytes());
    Ok(false)
}
fn hosted<A: Algorithm>(
    session: &mut host::Session<A>,
    key: &[u8],
    message: &[u8],
    candidate: Option<&Tags>,
    out: &mut Tags,
    bytes: usize,
) -> Result<bool> {
    if let Some(candidate) = candidate {
        return authentication(session.verify(
            host::Request {
                key,
                chunks: &[message],
                tail: host::Bits::empty(),
            },
            black_box(&candidate[0][..bytes]),
            &host::Cancellation::new(),
        ));
    }
    let tag = checked(session.authenticate(key, message))?;
    out[0][..bytes].copy_from_slice(black_box(tag.expose()));
    Ok(false)
}
fn actual_md5(report: md5_batch::Report, lanes: usize) -> Result<()> {
    if report.vector_width != lanes
        || report.inner.vector_blocks < lanes
        || report.outer.vector_blocks < lanes
    {
        return Err("required actual SIMD work absent".into());
    }
    Ok(())
}

fn authentication(
    value: std::result::Result<(), brynja_legacy_hmac_std::VerificationError<host::Error>>,
) -> Result<bool> {
    match value {
        Ok(()) => Ok(true),
        Err(brynja_legacy_hmac_std::VerificationError::Mismatch) => Ok(false),
        Err(brynja_legacy_hmac_std::VerificationError::Operation(error)) => {
            Err(format!("{error:?}"))
        }
    }
}
