pub fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;

    let mut hasher = sha3::Keccak256::new();
    hasher.update(data);
    let mut res = [0u8; 32];
    res.iter_mut()
        .zip(hasher.finalize().into_iter())
        .for_each(|(l, r)| *l = r);
    res
}
