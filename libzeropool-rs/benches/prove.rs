use criterion::{black_box, criterion_group, criterion_main, Criterion};
use libzeropool::{
    fawkes_crypto::{
        backend::bellman_groth16::{engines::Bn256, Parameters},
        ff_uint::Num,
    },
    native::boundednum::BoundedNum,
    POOL_PARAMS,
};
use libzeropool_rs::{
    client::{state::State, TxType, UserAccount},
    proof_groth16::prove_tx,
};

fn prove_tx_benchmark(c: &mut Criterion) {
    let state = State::init_test(POOL_PARAMS.clone());
    let acc = UserAccount::from_seed(&[0], state, POOL_PARAMS.clone());

    let tx = acc
        .create_tx(
            TxType::Deposit {
                fee: BoundedNum::new(Num::from(0)),
                deposit_amount: BoundedNum::new(Num::from(1)),
                outputs: vec![],
            },
            None,
            None,
        )
        .unwrap();

    let data = std::fs::read("./benches/transfer_params.bin").unwrap();
    let params = Parameters::<Bn256>::read(&mut data.as_slice(), true, true).unwrap();

    c.bench_function("prove_tx", |b| {
        b.iter(|| {
            prove_tx(&params, &*POOL_PARAMS, tx.public.clone(), tx.secret.clone());
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = prove_tx_benchmark
}
criterion_main!(benches);
