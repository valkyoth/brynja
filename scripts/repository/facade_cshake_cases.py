"""Public composition methods remain reachable, but cannot reopen spent owners."""

CASES = r'''
macro_rules! composition {
    ($test:ident, $name:ident) => {
        #[test]
        fn $test() {
            use api::sha3::{Fips202Output, Sha3PublicDeclassification as Public};
            let mut expected = [0; 33];
            let mut reference = api::sha3::$name::new(b"composition", b"domain").unwrap();
            reference.update(b"message").unwrap();
            reference.finalize_public(&mut expected, Public::acknowledge()).unwrap();

            let mut state = api::sha3::$name::new(b"composition", b"domain").unwrap();
            let mut untouched = [0x5a; 4];
            assert!(state.squeeze_public_in_place(&mut untouched, Public::acknowledge()).is_err());
            assert_eq!(untouched, [0x5a; 4]);
            state.update(b"message").unwrap();
            state.enter_squeezing_in_place(None).unwrap();
            assert!(state.update(b"reopen").is_err());
            assert!(state.enter_squeezing_in_place(None).is_err());
            let mut secret_bytes = [0xa5; 17];
            {
                let secret = state.squeeze_secret_in_place(&mut secret_bytes).unwrap();
                assert_eq!(secret.expose(), &expected[..17]);
            }
            assert_eq!(secret_bytes, [0; 17]);
            let mut tail = [0; 16];
            state.squeeze_final_bits_public_in_place(
                Fips202Output::new(&mut tail, 5).unwrap(), Public::acknowledge()).unwrap();
            expected[32] &= 0x1f;
            assert_eq!(tail, expected[17..]);
            assert!(state.update(b"reopen").is_err());
            assert!(state.squeeze_public_in_place(&mut untouched, Public::acknowledge()).is_err());
            assert_eq!(untouched, [0x5a; 4]);

            let mut source = api::sha3::$name::new(b"composition", b"domain").unwrap();
            source.update(b"message").unwrap();
            let mut reader = source.finalize_xof_erasing_source().unwrap();
            assert!(source.update(b"reopen").is_err());
            assert!(source.finalize_xof_erasing_source().is_err());
            let mut actual = [0; 33];
            reader.squeeze_final_bits_public_erasing_source(
                Fips202Output::new(&mut actual, 5).unwrap(), Public::acknowledge()).unwrap();
            assert_eq!(actual, expected);
            assert!(reader.squeeze_public(&mut untouched, Public::acknowledge()).is_err());
            assert_eq!(untouched, [0x5a; 4]);

            let mut cancelled = api::sha3::$name::new(b"composition", b"domain").unwrap();
            cancelled.wipe_in_place();
            assert!(cancelled.update(b"reopen").is_err());
            assert!(cancelled.enter_squeezing_in_place(None).is_err());
        }
    };
}
composition!(cshake128_composition_is_terminal, HardenedCshake128);
composition!(cshake256_composition_is_terminal, HardenedCshake256);
'''
