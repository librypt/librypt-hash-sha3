use librypt_hash::{Hash, HashFn};

use crate::keccak::Keccak;

pub struct Sha3_224 {
    keccak: Keccak<144, 0x06>,
}

impl HashFn<144, 28> for Sha3_224 {
    fn new() -> Self {
        Self {
            keccak: <_ as HashFn<144, 28>>::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        <_ as HashFn<144, 28>>::update(&mut self.keccak, data);
    }

    fn finalize(self) -> Hash<28> {
        self.keccak.finalize()
    }

    fn finalize_reset(&mut self) -> Hash<28> {
        self.keccak.finalize_reset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::ToHex;

    #[test]
    fn test_sha3_224() {
        let hash = Sha3_224::hash(b"Hello, world!");

        assert_eq!(
            hash.encode_hex::<String>(),
            "6a33e22f20f16642697e8bd549ff7b759252ad56c05a1b0acc31dc69"
        );
    }
}
