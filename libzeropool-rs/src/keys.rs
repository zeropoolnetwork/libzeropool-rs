use libzeropool::native::params::PoolParams;
use libzeropool::{
    fawkes_crypto::ff_uint::{Num, NumRepr, Uint},
    native::key::{derive_key_a, derive_key_eta},
    POOL_PARAMS,
};

pub fn reduce_sk(seed: &[u8]) -> Vec<u8> {
    let sk = Num::<Fs>::from_uint_reduced(NumRepr(Uint::from_little_endian(seed)));
    sk.to_uint().0.to_little_endian()
}

#[derive(Clone)]
pub struct Keys<P: PoolParams> {
    pub sk: Num<P::Fs>,
    pub a: Num<P::Fr>,
    pub eta: Num<P::Fr>,
}

impl<P: PoolParams> Keys<P> {
    pub fn derive(sk: Num<P::Fs>) -> Self {
        let a = derive_key_a(sk, &*POOL_PARAMS).x;
        let eta = derive_key_eta(a, &*POOL_PARAMS);

        Keys { sk: num_sk, a, eta }
    }
}
