"""Downstream family examples: public APIs only, no conformance/evidence cfgs."""

RUST = r'''
#[test]
fn sha2_named_bits_and_general_t() {
    use api::sha2::{self, execution as run, BitString, Sha512TBits};
    let input = BitString::new(&[0xa0], 3).unwrap();
    macro_rules! named {
        ($state:ident, $reference:ident) => {
            assert_eq!(run::$state::hash_bits(run::Execution::portable(), input).unwrap().digest,
                       sha2::$reference(input).unwrap());
        };
    }
    named!(Sha224, sha224_bits);
    named!(Sha256, sha256_bits);
    named!(Sha384, sha384_bits);
    named!(Sha512, sha512_bits);
    named!(Sha512_224, sha512_224_bits);
    named!(Sha512_256, sha512_256_bits);
    for width in [1, 7, 224, 255, 256, 511] {
        let parameter = Sha512TBits::new(width).unwrap();
        let expected = sha2::sha512_t_bits(parameter, input).unwrap();
        let result = run::Sha512T::hash_bits(parameter, run::Execution::portable(), input).unwrap();
        assert_eq!(result.digest, expected);
        assert_eq!(result.report.portable_iv_blocks, 1);
    }
    assert!(Sha512TBits::new(0).is_err());
    assert!(Sha512TBits::new(384).is_err());
    assert!(Sha512TBits::new(512).is_err());
}

#[test]
fn sha3_fixed_bits_shake_and_cshake() {
    use api::sha3::{self, execution as run, Fips202BitString, Fips202Output};
    let bits = Fips202BitString::new(&[5], 3).unwrap();
    macro_rules! fixed {
        ($state:ident, $reference:ident) => {
            assert_eq!(run::$state::hash_bits(run::Execution::portable(), run::PublicBits::new(bits))
                       .unwrap().digest, sha3::$reference(bits).unwrap());
        };
    }
    fixed!(Sha3_224, sha3_224_bits);
    fixed!(Sha3_256, sha3_256_bits);
    fixed!(Sha3_384, sha3_384_bits);
    fixed!(Sha3_512, sha3_512_bits);
    macro_rules! xof {
        ($state:ident, $reference:ident) => {{
            let mut expected = [0; 201];
            sha3::$reference(b"abc", &mut expected).unwrap();
            let mut state = run::$state::new(run::Execution::portable()).unwrap();
            state.update(run::Public::new(b"a")).unwrap();
            state.update(run::Public::new(b"bc")).unwrap();
            let mut reader = state.finalize_xof().unwrap();
            let mut actual = [0; 201];
            reader.squeeze(&mut actual[..7]).unwrap();
            reader.squeeze_with_scratch(&mut actual[7..], &mut [0; 194]).unwrap();
            assert_eq!(actual, expected);
        }};
    }
    xof!(Shake128, shake128);
    xof!(Shake256, shake256);
    macro_rules! customized {
        ($state:ident, $reference:ident) => {{
            let mut expected = [0; 200];
            sha3::$reference(b"abc", b"function", b"domain", &mut expected).unwrap();
            let mut state = run::$state::new(run::Execution::portable(),
                run::Public::new(b"function"), run::Public::new(b"domain")).unwrap();
            state.update(run::Public::new(b"abc")).unwrap();
            let mut actual = [0; 200];
            state.finalize_xof().unwrap().squeeze_with_scratch(&mut actual, &mut [0; 200]).unwrap();
            assert_eq!(actual, expected);
        }};
    }
    customized!(Cshake128, cshake128);
    customized!(Cshake256, cshake256);
    let mut actual = [0xff; 17];
    let mut expected = [0xff; 17];
    let mut plain = sha3::Shake128::new();
    plain.update(b"abc").unwrap();
    plain.finalize_xof().squeeze_final_bits(Fips202Output::new(&mut expected, 3).unwrap()).unwrap();
    let mut state = run::Shake128::new(run::Execution::portable()).unwrap();
    state.update(run::Public::new(b"abc")).unwrap();
    state.finalize_xof().unwrap()
        .squeeze_final_bits(Fips202Output::new(&mut actual, 3).unwrap()).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(actual[16] & 0xf8, 0);
}

#[test]
fn kmac_fixed_xof_and_full_strength_policy() {
    use api::kmac::{self, execution as run};
    // Public synthetic test material, not a production key.
    let key = [0x42; 32];
    macro_rules! fixed {
        ($state:ident) => {{
            let mut plain = kmac::$state::new(&key, b"domain").unwrap();
            let mut selected = run::$state::new(run::Mode::Portable, &key, b"domain").unwrap();
            plain.update(b"abc").unwrap();
            selected.update(b"a").unwrap();
            selected.update(b"bc").unwrap();
            let mut expected = [0; 32];
            let mut actual = [0; 32];
            let expected = plain.finalize_tag(&mut expected).unwrap();
            let actual = selected.finalize_tag(&mut actual).unwrap();
            assert_eq!(actual.verify_candidate(expected.as_bytes()), Ok(()));
            assert!(run::$state::new(run::Mode::Portable, &[0; 1], b"").is_err());
            assert!(run::$state::new(run::Mode::Require(None), &key, b"").is_err());
        }};
    }
    fixed!(Kmac128);
    fixed!(Kmac256);
    macro_rules! xof {
        ($state:ident) => {{
            let mut plain = kmac::$state::new(&key, b"domain").unwrap();
            let mut selected = run::$state::new(run::Mode::Portable, &key, b"domain").unwrap();
            plain.update(b"abc").unwrap();
            selected.update(b"abc").unwrap();
            let mut expected = [0; 200];
            let mut actual = [0; 200];
            {
                let mut plain_reader = plain.finalize_xof().unwrap();
                let mut reader = selected.finalize_xof().unwrap();
                let expected = plain_reader.squeeze_secret(&mut expected).unwrap();
                let actual = reader.squeeze_secret(&mut actual).unwrap();
                assert_eq!(actual.expose(), expected.expose());
            }
            assert_eq!(actual, [0; 200]);
            assert_eq!(expected, [0; 200]);
            assert!(selected.update(b"late").is_err());
        }};
    }
    xof!(KmacXof128);
    xof!(KmacXof256);
}

#[test]
fn tuplehash_framing_secret_and_xof() {
    use api::tuplehash::{self, execution as run, Fips202BitString};
    let tail = Fips202BitString::new(&[5], 3).unwrap();
    macro_rules! fixed {
        ($plain:ident, $secret:ident) => {{
            let mut expected = [0; 32];
            let mut plain = tuplehash::$plain::new(b"domain").unwrap();
            plain.push_item(b"abc").unwrap();
            plain.push_item_bits(tail).unwrap();
            plain.finalize(&mut expected).unwrap();
            let mut secret = run::$secret::new(run::Mode::Portable, b"domain").unwrap();
            let mut writer = secret.begin_item(24).unwrap();
            writer.update(b"a").unwrap();
            writer.update(b"bc").unwrap();
            writer.finish().unwrap();
            secret.push_item_bits(tail).unwrap();
            let mut actual = [0; 32];
            {
                let output = secret.finalize_secret(&mut actual).unwrap();
                assert_eq!(output.expose(), expected);
            }
            assert_eq!(actual, [0; 32]);
        }};
    }
    fixed!(TupleHash128, HardenedTupleHash128);
    fixed!(TupleHash256, HardenedTupleHash256);
    macro_rules! xof {
        ($state:ident) => {{
            let mut plain = tuplehash::$state::new(b"").unwrap();
            let mut selected = run::$state::new(run::Mode::Portable, b"").unwrap();
            plain.push_item(b"abc").unwrap();
            selected.push_item(b"abc").unwrap();
            let mut expected = [0; 200];
            let mut actual = [0; 200];
            plain.finalize_xof().unwrap().squeeze(&mut expected).unwrap();
            selected.finalize_xof().unwrap()
                .squeeze_with_scratch(&mut actual, &mut [0; 200]).unwrap();
            assert_eq!(actual, expected);
        }};
    }
    xof!(TupleHashXof128);
    xof!(TupleHashXof256);
}

#[test]
fn parallelhash_serial_and_batched_plan_binding() {
    use api::parallelhash::{self, execution as run};
    macro_rules! fixed {
        ($state:ident, $identity:ident) => {{
            let input = [0x5a; 33];
            let mut workspace = [0; 8];
            let mut plain = parallelhash::$state::new(&mut workspace, b"domain").unwrap();
            plain.update(&input).unwrap();
            let mut expected = [0; 32];
            plain.finalize(&mut expected).unwrap();
            for grouped in [false, true] {
                let plan = run::Plan::new(run::Identity::$identity, &input, 8, 5).unwrap();
                let mut root = run::Collector::new(&plan, run::Mode::Portable, b"domain").unwrap();
                if grouped {
                    let mut cancel = || false;
                    let report = root.execute_batched(&run::batch::Executor::portable(),
                        &mut run::batch::Workspace::new(),
                        &mut run::batch::Control::new(128, &mut cancel)).unwrap();
                    assert_eq!(report.leaves, 5);
                    assert_eq!(report.accelerated_leaves, 0);
                } else {
                    root.execute_serial(|_| Ok(run::Mode::Portable)).unwrap();
                }
                let mut actual = [0; 32];
                let mut scratch = [0xa5; 32];
                root.finalize_public(&mut actual, &mut scratch,
                    parallelhash::ParallelHashPublicDeclassification::acknowledge()).unwrap();
                assert_eq!(actual, expected);
                assert_eq!(scratch, [0; 32]);
            }
        }};
    }
    fixed!(ParallelHash128, ParallelHash128);
    fixed!(ParallelHash256, ParallelHash256);
}
'''
