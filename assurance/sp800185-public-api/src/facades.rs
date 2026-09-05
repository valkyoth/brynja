use brynja_hash_parallel::parallel_hash_xof128;
use brynja_hash_sha3::cshake128;
use brynja_hash_tuple::tuple_hash128;
use brynja_mac_kmac::kmac128;

use crate::AcceptanceError;

pub(crate) fn run() -> Result<(), AcceptanceError> {
    cshake_layers()?;
    kmac_layers()?;
    tuple_layers()?;
    parallel_layers()
}

fn cshake_layers() -> Result<(), AcceptanceError> {
    let mut leaf = [0_u8; 32];
    let mut crypto = [0_u8; 32];
    let mut main = [0_u8; 32];
    cshake128(b"facade", b"", b"acceptance", &mut leaf).map_err(|_| AcceptanceError::Facade)?;
    brynja_crypto::cshake128(b"facade", b"", b"acceptance", &mut crypto)
        .map_err(|_| AcceptanceError::Facade)?;
    brynja::crypto::cshake128(b"facade", b"", b"acceptance", &mut main)
        .map_err(|_| AcceptanceError::Facade)?;
    same(&leaf, &crypto, &main)
}

fn kmac_layers() -> Result<(), AcceptanceError> {
    let key = [0x42_u8; 16];
    let mut leaf = [0_u8; 16];
    let mut crypto = [0_u8; 16];
    let mut main = [0_u8; 16];
    let _leaf_tag =
        kmac128(&key, b"facade", b"acceptance", &mut leaf).map_err(|_| AcceptanceError::Facade)?;
    let _crypto_tag = brynja_crypto::kmac128(&key, b"facade", b"acceptance", &mut crypto)
        .map_err(|_| AcceptanceError::Facade)?;
    let _main_tag = brynja::crypto::kmac128(&key, b"facade", b"acceptance", &mut main)
        .map_err(|_| AcceptanceError::Facade)?;
    same(&leaf, &crypto, &main)
}

fn tuple_layers() -> Result<(), AcceptanceError> {
    let items: &[&[u8]] = &[b"one", b"two"];
    let mut leaf = [0_u8; 32];
    let mut crypto = [0_u8; 32];
    let mut main = [0_u8; 32];
    tuple_hash128(items, b"acceptance", &mut leaf).map_err(|_| AcceptanceError::Facade)?;
    brynja_crypto::tuple_hash128(items, b"acceptance", &mut crypto)
        .map_err(|_| AcceptanceError::Facade)?;
    brynja::crypto::tuple_hash128(items, b"acceptance", &mut main)
        .map_err(|_| AcceptanceError::Facade)?;
    same(&leaf, &crypto, &main)
}

fn parallel_layers() -> Result<(), AcceptanceError> {
    let mut leaf = [0_u8; 32];
    let mut crypto = [0_u8; 32];
    let mut main = [0_u8; 32];
    parallel_hash_xof128(b"facade", &mut [0; 3], b"acceptance", &mut leaf)
        .map_err(|_| AcceptanceError::Facade)?;
    brynja_crypto::parallel_hash_xof128(b"facade", &mut [0; 3], b"acceptance", &mut crypto)
        .map_err(|_| AcceptanceError::Facade)?;
    brynja::crypto::parallel_hash_xof128(b"facade", &mut [0; 3], b"acceptance", &mut main)
        .map_err(|_| AcceptanceError::Facade)?;
    same(&leaf, &crypto, &main)
}

fn same(leaf: &[u8], crypto: &[u8], main: &[u8]) -> Result<(), AcceptanceError> {
    if leaf == crypto && leaf == main {
        Ok(())
    } else {
        Err(AcceptanceError::Facade)
    }
}
