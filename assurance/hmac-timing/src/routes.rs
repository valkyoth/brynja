//! Explicit routes; resource/authority acquisition is outside measured requests.
#[cfg(target_os = "macos")]
use brynja_crypto_cpu_std::macos_resident::hmac as host;
#[cfg(not(target_os = "macos"))]
use brynja_crypto_cpu_std::strict_hmac as host;
use brynja_mac_hmac::{Hmac, execution};
use std::hint::black_box;

pub type Result<T> = std::result::Result<T, String>;
pub trait Algorithm: host::Algorithm + for<'a> execution::Algorithm<'a> {}
impl<A: host::Algorithm + for<'a> execution::Algorithm<'a>> Algorithm for A {}
fn checked<T, E: std::fmt::Debug>(value: std::result::Result<T, E>) -> Result<T> {
    value.map_err(|error| format!("{error:?}"))
}

pub enum Route<A: Algorithm> {
    Portable,
    Static(execution::Authority),
    Runtime(brynja_crypto_cpu_std::execution::Authority),
    Hosted(host::Session<A>),
    Compiled(host::CompiledSession<A>),
}

fn kernel(name: &str) -> Result<execution::Kernel> {
    use execution::Kernel::*;
    match (std::env::consts::ARCH, name) {
        ("x86_64", "sha256") => Ok(X86Sha256),
        ("x86_64", "sha512") => Ok(X86Sha512),
        ("x86_64", "keccak") => Ok(X86Keccak),
        ("aarch64", "sha256") => Ok(ArmSha256),
        ("aarch64", "sha512") => Ok(ArmSha512),
        ("aarch64", "keccak") => Ok(ArmKeccak),
        _ => Err("unsupported timing kernel".into()),
    }
}

impl<A: Algorithm> Route<A> {
    pub fn new(route: &str, family: &str, bytes: usize) -> Result<Self> {
        let limits = host::Limits {
            stack_bytes: 262144,
            max_stack_mapping_bytes: 1048576,
            max_buffer_mapping_bytes: 65536,
            max_key_bytes: 200,
            max_message_bits: 73 * 8,
            max_chunks: 1,
        };
        let policy = host::TagPolicy::Bytes(bytes);
        match route {
            "portable" => Ok(Self::Portable),
            "runtime" => {
                use brynja_crypto_cpu_std::execution::{Authority, Mode};
                Ok(Self::Runtime(checked(Authority::new(
                    kernel(family)?,
                    Mode::Require,
                ))?))
            }
            "static" => Ok(Self::Static(checked(execution::Authority::new(kernel(
                family,
            )?))?)),
            "linux-protected" if cfg!(all(target_os = "linux", target_env = "gnu")) => {
                Ok(Self::Hosted(checked(host::Session::new(policy, limits))?))
            }
            "macos-resident" if cfg!(all(target_os = "macos", target_arch = "aarch64")) => {
                Ok(Self::Hosted(checked(host::Session::new(policy, limits))?))
            }
            "linux-compiled" if cfg!(all(target_os = "linux", target_env = "gnu")) => {
                Ok(Self::Compiled(checked(host::CompiledSession::new(
                    policy,
                    kernel(family)?,
                    limits,
                ))?))
            }
            "macos-compiled" if cfg!(all(target_os = "macos", target_arch = "aarch64")) => {
                Ok(Self::Compiled(checked(host::CompiledSession::new(
                    policy,
                    kernel(family)?,
                    limits,
                ))?))
            }
            _ => Err("unsupported timing route/platform".into()),
        }
    }

    pub fn operation(
        &mut self,
        key: &[u8],
        candidate: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<bool> {
        let key = black_box(key);
        let message = black_box(&[0x37; 73]);
        match self {
            Self::Portable => {
                let mut state = checked(Hmac::<A>::with_tag_length(key, out.len()))?;
                checked(state.update(message))?;
                if let Some(candidate) = candidate {
                    return Ok(checked(state.verify(black_box(candidate)))?.expose_public());
                }
                black_box(checked(state.finalize_tag(out))?.as_bytes());
            }
            Self::Static(owner) => {
                let mut state = checked(execution::Hmac::<A>::from_static_with_tag_length(
                    owner,
                    key,
                    out.len(),
                ))?;
                checked(state.update(message))?;
                if let Some(candidate) = candidate {
                    return Ok(checked(state.verify(black_box(candidate)))?.expose_public());
                }
                black_box(checked(state.finalize_tag(out))?.as_bytes());
            }
            Self::Runtime(owner) => {
                let brynja_crypto_cpu_std::execution::HmacSelection::Accelerated(mut state) =
                    checked(owner.hmac_with_tag_length::<A>(key, out.len()))? else {
                        return Err("required runtime authority selected portable".into());
                    };
                checked(state.update(message))?;
                if let Some(candidate) = candidate {
                    return Ok(checked(state.verify(black_box(candidate)))?.expose_public());
                }
                black_box(checked(state.finalize_tag(out))?.as_bytes());
            }
            Self::Hosted(session) => {
                if let Some(candidate) = candidate {
                    return checked(session.verify(
                        host::Request {
                            key,
                            chunks: &[message],
                            tail: host::Bits::empty(),
                        },
                        black_box(candidate),
                        &host::Cancellation::new(),
                    ));
                }
                let tag = checked(session.authenticate(key, message))?;
                out.copy_from_slice(black_box(tag.expose()));
            }
            Self::Compiled(session) => {
                if let Some(candidate) = candidate {
                    return checked(session.verify(
                        host::Request {
                            key,
                            chunks: &[message],
                            tail: host::Bits::empty(),
                        },
                        black_box(candidate),
                        &host::Cancellation::new(),
                    ));
                }
                let tag = checked(session.authenticate(key, message))?;
                out.copy_from_slice(black_box(tag.expose()));
            }
        }
        Ok(false)
    }
}
