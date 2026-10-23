"""Compile forbidden downstream operations against the extracted public API."""
import subprocess

from legacy_hmac_acceptance import require

PRELUDE = ('#![no_std]\nuse brynja_legacy_hmac::{Error, Hmac, LegacyUse, Md5, Sha1, Tag};\n'
           'use brynja_legacy_hmac::execution::{Sha1Executor, Sha1Hmac};\n')
POSITIVE = ('pub fn probe(owner: &Sha1Executor) -> Result<(), Error> {\n'
            'let mut state = Sha1Hmac::new(LegacyUse::acknowledge(), owner, b"key")?;\n'
            'state.update(b"message")?; let mut output = [0; 20];\n'
            'let tag: Tag<Sha1> = state.finalize_tag(&mut output)?;\n'
            'let _ = tag.as_bytes(); Ok(()) }\n')
NEGATIVES = {
    "consumed": ('pub fn probe(owner: &Sha1Executor) -> Result<(), Error> { let mut state = Sha1Hmac::new(LegacyUse::acknowledge(), owner, b"key")?; state.cancel(); state.update(b"again") }', "E0382"),
    "executor-lifetime": ('pub fn probe(owner: Sha1Executor) -> Result<(), Error> { let state = Sha1Hmac::new(LegacyUse::acknowledge(), &owner, b"key")?; drop(owner); state.cancel(); Ok(()) }', "E0505"),
    "algorithm-substitution": ('pub fn probe(tag: Tag<Sha1>) -> Tag<Md5> { tag }', "E0308"),
    "private-rebind": ('pub fn probe(tag: Tag<Sha1>) { let _: Tag<Md5> = tag.rebind(); }', "E0624"),
    "missing-acknowledgement": ('pub fn probe(owner: &Sha1Executor) { let _ = Sha1Hmac::new(owner, b"key"); }', "E0061"),
    "preflight-oracle": ('pub fn probe(state: &Sha1Hmac) { let _ = state.check_additional_bits(u64::MAX); }', "E0599"),
    "ordinary-conversion": ('pub fn probe(state: Sha1Hmac) { let _: Hmac<Sha1> = state.into(); }', "E0277"),
    "modern-export": ('use brynja_legacy_hmac::Sha256;', "E0432"),
    "raw-authority-export": ('use brynja_legacy_hmac::execution::Authority;', "E0432"),
}
for bound in ("Send", "Sync", "Copy", "Clone", "core::fmt::Debug"):
    NEGATIVES["owner-" + bound] = (f"pub fn probe() {{ fn require<T: {bound}>() {{}} require::<Sha1Hmac<'static>>(); }}", "E0277")


def check(consumer, environment, run, cargo_environment):
    source = consumer / "src/lib.rs"
    original = source.read_bytes()
    command = ["cargo", "check", "--offline", "--locked", "--features", "sha1-execution", "--lib"]
    try:
        source.write_text(PRELUDE + POSITIVE)
        run(command, consumer, environment)
        for name, (body, expected) in NEGATIVES.items():
            source.write_text(PRELUDE + body)
            cargo_environment.check(consumer, environment)
            result = subprocess.run(command, cwd=consumer, env=environment, text=True, capture_output=True, timeout=60, check=False)
            require(result.returncode != 0 and f"error[{expected}]" in result.stderr,
                    "compiled negative did not reject for expected reason: " + name + "\n" + result.stderr[-2000:])
        source.write_text(PRELUDE + POSITIVE)
        run(command, consumer, environment)
    finally:
        source.write_bytes(original)
    print(f"Extracted legacy HMAC: {len(NEGATIVES)} ownership/identity/authority operations rejected")
