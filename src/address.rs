use libzeropool::fawkes_crypto::borsh::{BorshDeserialize, BorshSerialize};
use libzeropool::fawkes_crypto::ff_uint::{Num, NumRepr, Uint};
use libzeropool::native::params::PoolParams;
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

pub fn parse_address<P: PoolParams>(address: &str) -> Result<(Num<P::Fr>, Num<P::Fr>), ParseError> {
    let mut bytes = [0; ADDR_LEN];
    bs58::decode(address).into(&mut bytes)?;

    let mut d_bytes = [0; 32];
    d_bytes[0..10].clone_from_slice(&bytes[0..10]);
    let mut p_d_bytes = [0; 32];
    p_d_bytes[0..32].clone_from_slice(&bytes[10..42]);
    let checksum = &bytes[42..=45];

    let mut hasher = Sha256::new();
    hasher.update(&bytes[0..=41]);
    let hash = hasher.finalize();

    if &hash[0..=3] != checksum {
        return Err(ParseError::InvalidChecksum);
    }

    let d = Num::try_from_slice(&d_bytes)?;
    let p_d = Num::try_from_slice(&p_d_bytes)?;

    Ok((d, p_d))
}

pub fn format_address<P: PoolParams>(d: Num<P::Fr>, p_d: Num<P::Fr>) -> String {
    let mut buf: [u8; ADDR_LEN] = [0; ADDR_LEN];

    let mut d_bytes = [0; 32];
    d.serialize(&mut &mut d_bytes[..]).unwrap();
    buf[0..10].clone_from_slice(&d_bytes[0..10]);

    p_d.serialize(&mut &mut buf[10..42]).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(&buf[0..42]);
    let hash = hasher.finalize();
    buf[42..ADDR_LEN].clone_from_slice(&hash[0..4]);

    bs58::encode(buf).into_string()
}
