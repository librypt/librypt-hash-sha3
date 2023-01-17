use librypt_hash::{Hash, HashFn};

use crate::keccak::Keccak;

pub struct Shake256 {
    keccak: Keccak<136, 0x1f>,
}

impl<const OUTPUT_SIZE: usize> HashFn<136, OUTPUT_SIZE> for Shake256 {
    fn new() -> Self {
        Self {
            keccak: <_ as HashFn<136, OUTPUT_SIZE>>::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        <_ as HashFn<136, OUTPUT_SIZE>>::update(&mut self.keccak, data);
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
    fn test_shake256() {
        let hash: [u8; 64] = Shake256::hash(b"Hello, world!");

        assert_eq!(
            hash.encode_hex::<String>(),
            "cf68a0d388047ed588ad72d3808cf9a3243f04d4901748c705fbf3a27d955542fd9d53af53e84c8abd4fce6e224af9a0a9e7eea5573a886b1af8c29f9897c8b5"
        );
    }
}
