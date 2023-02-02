use libzeropool::{
    fawkes_crypto::ff_uint::{Num, NumRepr, PrimeField, Uint},
    native::{
        key::{derive_key_a, derive_key_eta},
        params::PoolParams,
    },
};
use serde::{Deserialize, Serialize};

pub fn reduce_sk<Fs: PrimeField>(seed: &[u8]) -> Num<Fs> {
    Num::<Fs>::from_uint_reduced(NumRepr(Uint::from_little_endian(seed)))
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Keys<P: PoolParams> {
    pub sk: Num<P::Fs>,
    pub a: Num<P::Fr>,
    pub eta: Num<P::Fr>,
}

impl<P: PoolParams> Keys<P> {
    pub fn derive(sk: Num<P::Fs>, params: &P) -> Self {
        let a = derive_key_a(sk, params).x;
        let eta = derive_key_eta(a, params);

        Keys { sk, a, eta }
    }
}
