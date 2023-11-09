// Using a trait would probably be an overkill here.

use byteorder::{BigEndian, LittleEndian, WriteBytesExt};
use zeropool_state::libzeropool::fawkes_crypto::{engines::U256, ff_uint::Uint};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Backend {
    Evm,
    Near,
    Substrate,
    Waves,
}

impl Backend {
    pub fn sign_deposit_data<F: Fn(&[u8]) -> Vec<u8>>(
        &self,
        nullifier: U256,
        from_address: &str,
        deposit_id: u64,
        sign: F,
    ) -> Vec<u8> {
        match self {
            Backend::Evm => {
                sign(&nullifier.to_big_endian()) // FIXME: convert to compact signature
            }
            Backend::Near => {
                let mut data = Vec::new();
                data.extend_from_slice(&nullifier.to_little_endian());
                data.write_u32::<LittleEndian>(from_address.len() as u32)
                    .unwrap();
                data.extend_from_slice(from_address.as_bytes());
                data.write_u64::<LittleEndian>(deposit_id).unwrap();
                let signature = sign(&data);

                let mut data = Vec::new();
                data.extend_from_slice(&signature);
                data.write_u32::<LittleEndian>(from_address.len() as u32)
                    .unwrap();
                data.extend_from_slice(from_address.as_bytes());
                data.write_u64::<LittleEndian>(deposit_id).unwrap();
                data
            }
            Backend::Substrate => sign(&nullifier.to_big_endian()),
            Backend::Waves => {
                let mut data = Vec::new();
                data.extend_from_slice(&nullifier.to_big_endian());
                data.write_u32::<BigEndian>(from_address.len() as u32)
                    .unwrap();
                data.extend_from_slice(from_address.as_bytes());
                let signature = sign(&data);

                let mut data = Vec::new();
                data.extend_from_slice(&signature);
                data.write_u32::<BigEndian>(from_address.len() as u32)
                    .unwrap();
                data.extend_from_slice(from_address.as_bytes());
                data
            }
        }
    }
}
