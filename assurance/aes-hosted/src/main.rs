//! Baseline-compiled downstream owner exercise. Expected route is mandatory.
#![forbid(unsafe_code)]
use brynja_crypto::aes::{PublicCiphertext, execution::*};
use brynja_crypto_cpu_std::aes::{self as hosted, Mode, Route};

fn field<const N: usize>(line: &str, prefix: &str) -> [u8; N] {
    let text = line.strip_prefix(prefix).expect("field prefix");
    assert_eq!(text.len(), N * 2);
    let mut out = [0; N];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *slot = u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hex");
    }
    out
}

macro_rules! cases {
    ($run:ident, $key:ident, $cached:ident, $bits:literal, $k:literal, $s:literal, $gfs:literal, $box:literal, $total:literal) => {
        fn $run(authority: &Authority) {
            let mut count = 0;
            for (text, expected) in [
                (
                    include_str!(concat!(
                        "../../../crates/brynja-crypto/tests/fixtures/aes",
                        $bits,
                        "/ECBGFSbox",
                        $bits,
                        ".rsp"
                    )),
                    $gfs,
                ),
                (
                    include_str!(concat!(
                        "../../../crates/brynja-crypto/tests/fixtures/aes",
                        $bits,
                        "/ECBKeySbox",
                        $bits,
                        ".rsp"
                    )),
                    $box,
                ),
                (
                    include_str!(concat!(
                        "../../../crates/brynja-crypto/tests/fixtures/aes",
                        $bits,
                        "/ECBVarKey",
                        $bits,
                        ".rsp"
                    )),
                    $bits * 2,
                ),
                (
                    include_str!(concat!(
                        "../../../crates/brynja-crypto/tests/fixtures/aes",
                        $bits,
                        "/ECBVarTxt",
                        $bits,
                        ".rsp"
                    )),
                    256,
                ),
            ] {
                let lines: Vec<_> = text
                    .lines()
                    .map(str::trim)
                    .filter(|line| {
                        line.starts_with("KEY = ")
                            || line.starts_with("PLAINTEXT = ")
                            || line.starts_with("CIPHERTEXT = ")
                    })
                    .collect();
                assert_eq!(lines.len(), expected * 3);
                for record in lines.chunks_exact(3) {
                    let input_key = field::<$k>(
                        record
                            .iter()
                            .find(|s| s.starts_with("KEY = "))
                            .expect("key"),
                        "KEY = ",
                    );
                    let plain = field::<16>(
                        record
                            .iter()
                            .find(|s| s.starts_with("PLAINTEXT = "))
                            .expect("plain"),
                        "PLAINTEXT = ",
                    );
                    let cipher = field::<16>(
                        record
                            .iter()
                            .find(|s| s.starts_with("CIPHERTEXT = "))
                            .expect("cipher"),
                        "CIPHERTEXT = ",
                    );
                    let mut key_store = [0xa5; $k];
                    let mut schedule_store = [0xa5; $s];
                    let key = $key::new(authority, &input_key, &mut key_store).expect("key owner");
                    let cached = $cached::new(authority, &input_key, &mut schedule_store)
                        .expect("cached owner");
                    let mut out = [0xa5; 16];
                    for inverse in [false, true] {
                        let expected = if inverse { plain } else { cipher };
                        let actual = if inverse {
                            key.decrypt_block(&cipher, &mut out)
                        } else {
                            key.encrypt_block(&plain, &mut out)
                        }
                        .expect("ordinary operation");
                        assert_eq!(actual.expose(), &expected);
                        drop(actual);
                        assert_eq!(out, [0; 16]);
                        let actual = if inverse {
                            cached.decrypt_block(&cipher, &mut out)
                        } else {
                            cached.encrypt_block(&plain, &mut out)
                        }
                        .expect("cached operation");
                        assert_eq!(actual.expose(), &expected);
                        drop(actual);
                        assert_eq!(out, [0; 16]);
                    }
                    key.encrypt_block_public(&plain, &mut out, PublicCiphertext::acknowledge())
                        .expect("public ordinary");
                    assert_eq!(out, cipher);
                    cached
                        .encrypt_block_public(&plain, &mut out, PublicCiphertext::acknowledge())
                        .expect("public cached");
                    assert_eq!(out, cipher);
                    key.clear();
                    cached.clear();
                    assert_eq!(key_store, [0; $k]);
                    assert_eq!(schedule_store, [0; $s]);
                    count += 1;
                }
            }
            assert_eq!(count, $total);
            println!("AES_HOSTED_KAT_PASS: {}:{}", $bits, count);
        }
    };
}
cases!(
    aes128,
    Aes128Key,
    Aes128ExpandedKey,
    128,
    16,
    176,
    14,
    42,
    568
);
cases!(
    aes192,
    Aes192Key,
    Aes192ExpandedKey,
    192,
    24,
    208,
    12,
    48,
    700
);
cases!(
    aes256,
    Aes256Key,
    Aes256ExpandedKey,
    256,
    32,
    240,
    10,
    32,
    810
);

fn main() {
    let expect = std::env::args()
        .nth(1)
        .expect("accelerated or unavailable required");
    assert!(matches!(expect.as_str(), "accelerated" | "unavailable"));
    let kernel = if cfg!(target_arch = "x86_64") {
        Kernel::X86AesNi
    } else {
        Kernel::ArmAes
    };
    let selection = hosted::Authority::new(kernel, Mode::Prefer).expect("select");
    if expect == "unavailable" {
        assert!(matches!(
            selection.report().route,
            Route::PortableFallback(_)
        ));
        assert!(
            selection
                .kernel_authority()
                .expect("portable route")
                .is_none()
        );
        assert!(matches!(
            hosted::Authority::new(kernel, Mode::Require),
            Err(hosted::Error::Unavailable(_))
        ));
        println!("AES_HOSTED_UNAVAILABLE_PASS");
        return;
    }
    assert_eq!(selection.report().route, Route::Accelerated);
    let owner = selection
        .kernel_authority()
        .expect("healthy")
        .expect("hardware required");
    aes128(owner);
    aes192(owner);
    aes256(owner);
    let mut storage = [0; 16];
    let key = Aes128Key::new(owner, &[0; 16], &mut storage).expect("borrow owner");
    selection.quarantine();
    let mut output = [0xa5; 16];
    assert!(key.encrypt_block(&[0; 16], &mut output).is_err());
    assert_eq!(output, [0; 16]);
    output.fill(0xa5);
    assert!(
        key.encrypt_block_public(&[0; 16], &mut output, PublicCiphertext::acknowledge())
            .is_err()
    );
    assert_eq!(output, [0xa5; 16]);
    assert!(selection.kernel_authority().is_err());
    assert_eq!(selection.report().route, Route::Accelerated);
    println!("AES_HOSTED_ACCELERATED_PASS");
}
