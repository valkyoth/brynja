//! Shared PUBLIC-API consumer cases; no implementation/private-state access.
macro_rules! profile {
    ($state:ty, $hardened:ty, $hash:path, $bits:path, $size:expr, $counter:ty) => {
        pub(crate) fn bytes(data: &[u8], expected: &[u8]) {
            assert_eq!($hash(data).as_ref().map(|v| v.as_slice()), Ok(expected));
            for chunk in [1, 7, 31, 64, 113] {
                let mut state = <$state>::default();
                let mut hardened = <$hardened>::new();
                assert_eq!(state.message_bits(), 0);
                assert!(state.check_additional_bytes(data.len()).is_ok());
                assert!(
                    state
                        .check_additional_bits(data.len() as $counter * 8)
                        .is_ok()
                );
                assert!(hardened.check_additional_bytes(data.len()).is_ok());
                assert!(
                    hardened
                        .check_additional_bits(data.len() as $counter * 8)
                        .is_ok()
                );
                for piece in data.chunks(chunk) {
                    assert!(state.update(piece).is_ok());
                    assert!(hardened.update(piece).is_ok());
                }
                assert_eq!(state.message_bits(), data.len() as $counter * 8);
                assert_eq!(state.finalize().as_slice(), expected);
                let mut public = [0xa5; $size];
                assert!(
                    hardened
                        .finalize_public(&mut public, PublicDeclassification::acknowledge())
                        .is_ok()
                );
                assert_eq!(public.as_slice(), expected);
            }
            let mut state = <$state>::new();
            let mut hardened = <$hardened>::new();
            let mut remaining = data;
            for width in [1, 7, 31, 64, 113].into_iter().cycle() {
                if remaining.is_empty() {
                    break;
                }
                let (piece, rest) = remaining.split_at(width.min(remaining.len()));
                assert!(state.update(piece).is_ok());
                assert!(hardened.update(piece).is_ok());
                remaining = rest;
            }
            assert_eq!(state.finalize().as_slice(), expected);
            let mut public = [0xa5; $size];
            assert!(
                hardened
                    .finalize_public(&mut public, PublicDeclassification::acknowledge())
                    .is_ok()
            );
            assert_eq!(public.as_slice(), expected);
            let mut output = [0xa5; $size];
            {
                let result = <$hardened>::digest_secret(data, &mut output);
                assert!(result.is_ok());
                if let Ok(owner) = result {
                    assert_eq!(owner.expose(), expected);
                }
            }
            assert_eq!(output, [0; $size]);
            let mut state = <$hardened>::default();
            assert!(state.update(data).is_ok());
            {
                let result = state.finalize_secret(&mut output);
                assert!(result.is_ok());
                if let Ok(owner) = result {
                    assert_eq!(owner.expose(), expected);
                }
            }
            assert_eq!(output, [0; $size]);
        }

        pub(crate) fn bits(data: &[u8], width: u8, expected: &[u8]) {
            let input = BitString::new(data, width);
            assert!(input.is_ok());
            if let Ok(input) = input {
                assert_eq!($bits(input).as_ref().map(|v| v.as_slice()), Ok(expected));
                let empty = <$state>::new();
                assert_eq!(
                    empty.finalize_bits(input).as_ref().map(|v| v.as_slice()),
                    Ok(expected)
                );
                // Absorb a byte prefix then append the identical canonical tail.
                let split = data.len().saturating_sub(1);
                let tail = BitString::new(&data[split..], width);
                assert!(tail.is_ok());
                if let Ok(tail) = tail {
                    let mut state = <$state>::new();
                    let mut hardened = <$hardened>::new();
                    assert!(state.update(&data[..split]).is_ok());
                    assert!(hardened.update(&data[..split]).is_ok());
                    assert_eq!(
                        state.finalize_bits(tail).as_ref().map(|v| v.as_slice()),
                        Ok(expected)
                    );
                    let mut public = [0xa5; $size];
                    assert!(
                        hardened
                            .finalize_bits_public(
                                tail,
                                &mut public,
                                PublicDeclassification::acknowledge()
                            )
                            .is_ok()
                    );
                    assert_eq!(public.as_slice(), expected);
                }
                let mut output = [0xa5; $size];
                {
                    let result = <$hardened>::digest_bits_secret(input, &mut output);
                    assert!(result.is_ok());
                    if let Ok(owner) = result {
                        assert_eq!(owner.expose(), expected);
                    }
                }
                assert_eq!(output, [0; $size]);
                {
                    let result = <$hardened>::new().finalize_bits_secret(input, &mut output);
                    assert!(result.is_ok());
                    if let Ok(owner) = result {
                        assert_eq!(owner.expose(), expected);
                    }
                }
                assert_eq!(output, [0; $size]);
            }
        }

        pub(crate) fn failures() {
            assert!(BitString::new(&[1], 1).is_err());
            assert!(BitString::new(&[0], 9).is_err());
            let mut state = <$state>::new();
            let mut hardened = <$hardened>::new();
            assert!(state.update(b"a").is_ok());
            assert!(hardened.update(b"a").is_ok());
            assert!(state.check_additional_bits(<$counter>::MAX).is_err());
            assert!(hardened.check_additional_bits(<$counter>::MAX).is_err());
            assert_eq!(state.message_bits(), 8);
            assert_eq!(
                state.finalize().as_slice(),
                $hash(b"a").as_ref().map(|v| v.as_slice()).unwrap_or(&[])
            );
            // Cancellation is ownership drop; private clearing is checked by
            // separate exact-owner compiler and leaf lifecycle evidence.
            drop(hardened);
            let mut output = [0xa5; 1];
            assert!(
                <$hardened>::new()
                    .finalize_public(&mut output, PublicDeclassification::acknowledge())
                    .is_err()
            );
            assert_eq!(output, [0xa5; 1]);
            assert!(
                <$hardened>::new()
                    .finalize_secret(&mut output)
                    .map(drop)
                    .is_err()
            );
            assert_eq!(output, [0; 1]);
        }
    };
}
