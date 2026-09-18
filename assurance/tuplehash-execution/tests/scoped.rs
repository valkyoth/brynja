use brynja_hash_tuple::{
    Fips202BitString, TupleHashError as Error, TupleHashPublicDeclassification as Public,
    hardened_in_place as api,
};

macro_rules! check {
    ($name:ident, $workspace:ident, $reference:ident) => {
        #[test]
        fn $name() -> Result<(), Error> {
            let mut reference = brynja_hash_tuple::$reference::new(b"downstream")?;
            reference.push_item(b"first")?;
            reference.push_item_bits(
                Fips202BitString::new(&[0x5d, 0x15], 5).map_err(|_| Error::InvalidBitString)?,
            )?;
            let mut expected = [0; 32];
            reference.finalize(&mut expected)?;
            let mut workspace = api::$workspace::new();
            let mut bytes = [0xa5; 32];
            let secret = workspace.with(b"downstream", |mut state| {
                state.push_item(b"first")?;
                let mut writer = state.begin_item(13)?;
                writer.update_bits(
                    Fips202BitString::new(&[5], 3).map_err(|_| Error::InvalidBitString)?,
                )?;
                writer.update_bits(
                    Fips202BitString::new(&[3], 2).map_err(|_| Error::InvalidBitString)?,
                )?;
                writer.update(&[0xaa])?;
                writer.finish()?;
                state.finalize_secret(&mut bytes)
            })??;
            assert_eq!(secret.expose(), expected);
            drop(secret);
            assert_eq!(bytes, [0; 32]);
            workspace.with(b"", |mut state| -> Result<(), Error> {
                let mut item = state.begin_item(8)?;
                item.update(b"x")?;
                core::mem::forget(item);
                bytes.fill(0xa5);
                assert!(state.finalize_secret(&mut bytes).is_err());
                assert_eq!(bytes, [0; 32]);
                Ok(())
            })??;
            workspace.with(b"", |mut state| -> Result<(), Error> {
                drop(state.begin_item(0)?);
                bytes.fill(0xa5);
                assert!(
                    state
                        .finalize_public(&mut bytes, Public::acknowledge())
                        .is_err()
                );
                assert_eq!(bytes, [0xa5; 32]);
                Ok(())
            })??;
            workspace.with(b"downstream", |mut state| {
                state.push_item(b"first")?;
                state.push_item_bits(
                    Fips202BitString::new(&[0x5d, 0x15], 5).map_err(|_| Error::InvalidBitString)?,
                )?;
                state.finalize_public(&mut bytes, Public::acknowledge())
            })??;
            assert_eq!(bytes, expected);
            Ok(())
        }
    };
}
check!(
    scoped_tuple128_external_owner_api,
    TupleHash128Workspace,
    TupleHash128
);
check!(
    scoped_tuple256_external_owner_api,
    TupleHash256Workspace,
    TupleHash256
);

macro_rules! xof {
    ($test:ident, $workspace:ident, $reference:ident) => {
        #[test]
        fn $test() -> Result<(), Error> {
            let mut reference = brynja_hash_tuple::$reference::new(b"downstream")?;
            reference.push_item(b"first")?;
            reference.push_item_bits(
                Fips202BitString::new(&[5], 3).map_err(|_| Error::InvalidBitString)?,
            )?;
            let mut expected = [0; 400];
            reference.finalize_xof()?.squeeze(&mut expected)?;
            let mut workspace = api::$workspace::new();
            let mut output = [0xa5; 400];
            let secret = workspace.with(b"downstream", |mut state| {
                state.push_item(b"first")?;
                let mut item = state.begin_item(3)?;
                item.update_bits(
                    Fips202BitString::new(&[5], 3).map_err(|_| Error::InvalidBitString)?,
                )?;
                item.finish()?;
                state
                    .finalize_xof()?
                    .squeeze_final_bits_secret(&mut output, 8)
            })??;
            assert_eq!(secret.expose(), expected);
            drop(secret);
            assert_eq!(output, [0; 400]);
            workspace.with(b"downstream", |mut state| {
                state.push_item(b"first")?;
                state.push_item_bits(
                    Fips202BitString::new(&[5], 3).map_err(|_| Error::InvalidBitString)?,
                )?;
                let mut reader = state.finalize_xof()?;
                for chunk in output.chunks_mut(17) {
                    reader.squeeze_public(chunk, Public::acknowledge())?;
                }
                reader.cancel();
                Ok::<(), Error>(())
            })??;
            assert_eq!(output, expected);
            workspace.with(b"", |mut state| -> Result<(), Error> {
                core::mem::forget(state.begin_item(0)?);
                assert!(state.finalize_xof().is_err());
                Ok(())
            })??;
            let result = workspace.with(b"", |state| {
                state
                    .finalize_xof()?
                    .squeeze_final_bits_secret(&mut output, 9)
            })?;
            assert_eq!(result.map(drop), Err(Error::InvalidBitString));
            assert_eq!(output, [0; 400]);
            Ok(())
        }
    };
}
xof!(
    scoped_tuplexof128_external_owner_api,
    TupleHashXof128Workspace,
    TupleHashXof128
);
xof!(
    scoped_tuplexof256_external_owner_api,
    TupleHashXof256Workspace,
    TupleHashXof256
);
