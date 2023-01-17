use librypt_hash::{Hash, HashFn};

use crate::keccak::Keccak;

pub struct Shake128 {
    keccak: Keccak<168, 0x1f>,
}

impl<const OUTPUT_SIZE: usize> HashFn<168, OUTPUT_SIZE> for Shake128 {
    fn new() -> Self {
        Self {
            keccak: <_ as HashFn<168, OUTPUT_SIZE>>::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        <_ as HashFn<168, OUTPUT_SIZE>>::update(&mut self.keccak, data);
    }

    fn finalize(self) -> Hash<OUTPUT_SIZE> {
        self.keccak.finalize()
    }

    fn finalize_reset(&mut self) -> Hash<OUTPUT_SIZE> {
        self.keccak.finalize_reset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::ToHex;

    #[test]
    fn test_shake128() {
        let hash: [u8; 32] = Shake128::hash(b"Hello, world!");

        assert_eq!(
            hash.encode_hex::<String>(),
            "b5ffd113fa127f4d9c7e483cb52264ed413554ef899c0cf7c1d736ddb93313a6"
        );
    }
}
