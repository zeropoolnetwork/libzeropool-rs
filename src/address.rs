use libzeropool::{
    constants,
    fawkes_crypto::borsh::{BorshDeserialize, BorshSerialize},
    fawkes_crypto::ff_uint::Num,
    native::boundednum::BoundedNum,
    native::params::PoolParams,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

const ADDR_LEN: usize = 46;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Invalid checksum")]
    InvalidChecksum,
    #[error("Decode error: {0}")]
    Base58DecodeError(#[from] bs58::decode::Error),
    #[error("Deserialization error: {0}")]
    DeserializationError(#[from] std::io::Error),
}

pub fn parse_address<P: PoolParams>(
    address: &str,
) -> Result<
    (
        BoundedNum<P::Fr, { constants::DIVERSIFIER_SIZE }>,
        Num<P::Fr>,
    ),
    ParseError,
> {
    let mut bytes = [0; ADDR_LEN];
    bs58::decode(address).into(&mut bytes)?;

    let checksum = &bytes[42..=45];

    let mut hasher = Sha256::new();
    hasher.update(&bytes[0..=41]);
    let hash = hasher.finalize();

    if &hash[0..=3] != checksum {
        return Err(ParseError::InvalidChecksum);
    }

    let d = BoundedNum::try_from_slice(&bytes[0..10])?;
    let p_d = Num::try_from_slice(&bytes[10..42])?;

    Ok((d, p_d))
}

pub fn format_address<P: PoolParams>(
    d: BoundedNum<P::Fr, { constants::DIVERSIFIER_SIZE }>,
    p_d: Num<P::Fr>,
) -> String {
    let mut buf: [u8; ADDR_LEN] = [0; ADDR_LEN];

    d.serialize(&mut &mut buf[0..10]).unwrap();
    p_d.serialize(&mut &mut buf[10..42]).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(&buf[0..42]);
    let hash = hasher.finalize();
    buf[42..ADDR_LEN].clone_from_slice(&hash[0..4]);

    bs58::encode(buf).into_string()
}
