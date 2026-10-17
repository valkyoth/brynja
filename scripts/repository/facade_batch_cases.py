"""Ordinary transaction and hardened clearing checks via facade batch paths."""

RUST = r'''
#[test]
fn ordinary_sha2_batches_commit_transactionally() {
    macro_rules! check {
        ($module:ident, $algorithm:ident, $reference:ident) => {{
            use api::sha2::$module as batch;
            let bits = api::sha2::BitString::new(b"abc", 8).unwrap();
            let mut inputs = [None; batch::CAPACITY];
            inputs[0] = Some(batch::Input::new(batch::Algorithm::$algorithm, bits));
            let expected = api::sha2::$reference(b"abc").unwrap();
            let mut actual = [None; batch::CAPACITY];
            let mut cancelled = || false;
            let executor = batch::Executor::portable();
            let report = executor.digest(batch::PublicData::new(&inputs), &mut actual,
                &mut batch::Control::new(8, &mut cancelled)).unwrap();
            assert_eq!(actual[0], Some(batch::Digest::$algorithm(expected)));
            assert_eq!(report.vector_calls, 0);
            let saved = actual;
            assert!(executor.digest(batch::PublicData::new(&inputs), &mut actual,
                &mut batch::Control::new(0, &mut cancelled)).is_err());
            assert_eq!(actual, saved);
        }};
    }
    check!(batch, Sha224, sha224);
    check!(batch, Sha256, sha256);
    check!(batch512, Sha384, sha384);
    check!(batch512, Sha512, sha512);
    check!(batch512, Sha512_224, sha512_224);
    check!(batch512, Sha512_256, sha512_256);
}

#[test]
fn hardened_sha2_batches_clear_on_drop_and_rejection() {
    macro_rules! check {
        ($module:ident, $algorithm:ident, $reference:ident, $width:literal) => {{
            use api::sha2::$module as batch;
            let bits = api::sha2::BitString::new(b"abc", 8).unwrap();
            let mut inputs = core::array::from_fn(|_| None);
            inputs[0] = Some(batch::Input::new(batch::Algorithm::$algorithm, bits));
            let expected = api::sha2::$reference(b"abc").unwrap();
            let mut workspace = batch::Workspace::new();
            let executor = batch::Executor::portable();
            for budget in [8, 0] {
                let mut actual = [0xa5; $width];
                let mut destinations = core::array::from_fn(|_| None);
                destinations[0] = Some(actual.as_mut_slice());
                let mut cancelled = || false;
                {
                    let result = executor.digest_secret(&inputs, destinations, &mut workspace,
                        &mut batch::Control::new(budget, &mut cancelled));
                    if budget == 0 {
                        assert!(result.is_err());
                    } else {
                        let (output, report) = result.unwrap();
                        assert_eq!(output.expose(0).unwrap(), expected.as_bytes());
                        assert_eq!(report.vector_calls, 0);
                    }
                }
                assert_eq!(actual, [0; $width]);
            }
        }};
    }
    check!(hardened_batch, Sha224, sha224, 28);
    check!(hardened_batch, Sha256, sha256, 32);
    check!(hardened_batch512, Sha384, sha384, 48);
    check!(hardened_batch512, Sha512, sha512, 64);
    check!(hardened_batch512, Sha512_224, sha512_224, 28);
    check!(hardened_batch512, Sha512_256, sha512_256, 32);
}

#[test]
fn keccak_batches_keep_public_and_secret_profiles_distinct() {
    use api::sha3::{self, batch, hardened_batch as secret, Fips202BitString};
    let message = Fips202BitString::new(b"abc", 8).unwrap();
    let input = batch::Input::new(batch::Algorithm::Sha3_256, message, 256).unwrap();
    let expected = sha3::sha3_256(b"abc").unwrap();
    let mut actual = [0xa5; 32];
    let mut cancelled = || false;
    let executor = batch::Executor::portable();
    executor.digest(batch::PublicData::new(&[input]), &mut [&mut actual],
        &mut batch::Workspace::new(), &mut [0; 32],
        &mut batch::Control::new(8, &mut cancelled)).unwrap();
    assert_eq!(actual, *expected.as_bytes());
    let saved = actual;
    assert!(executor.digest(batch::PublicData::new(&[input]), &mut [&mut actual],
        &mut batch::Workspace::new(), &mut [0; 32],
        &mut batch::Control::new(0, &mut cancelled)).is_err());
    assert_eq!(actual, saved);
    let mut inputs = core::array::from_fn(|_| None);
    inputs[0] = Some(secret::Input::new(secret::Algorithm::Sha3_256, message, 256).unwrap());
    for budget in [8, 0] {
        let mut destination = [0xa5; 32];
        let mut destinations = core::array::from_fn(|_| None);
        destinations[0] = Some(destination.as_mut_slice());
        let mut staging = [0xa5; 32];
        {
            let result = secret::Executor::portable().digest_secret(&inputs, destinations,
                &mut secret::Workspace::new(), &mut staging,
                &mut secret::Control::new(budget, &mut cancelled));
            if budget == 0 {
                assert!(result.is_err());
            } else {
                let (output, report) = result.unwrap();
                assert_eq!(output.expose(0).unwrap(), expected.as_bytes());
                assert_eq!(report.vector_calls, 0);
            }
        }
        assert_eq!(destination, [0; 32]);
        assert_eq!(staging, [0; 32]);
    }
}
'''
