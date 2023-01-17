use librypt_hash::{Hash, HashFn};

use crate::keccak::Keccak;

pub struct Sha3_256 {
    keccak: Keccak<136, 0x06>,
}

impl HashFn<136, 32> for Sha3_256 {
    fn new() -> Self {
        Self {
            keccak: <_ as HashFn<136, 32>>::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        <_ as HashFn<136, 32>>::update(&mut self.keccak, data);
    }

    fn finalize(self) -> Hash<32> {
        self.keccak.finalize()
    }

    fn finalize_reset(&mut self) -> Hash<32> {
        self.keccak.finalize_reset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::ToHex;

    #[test]
    fn test_sha3_256() {
        let hash = Sha3_256::hash(b"Hello, world!");

        assert_eq!(
            hash.encode_hex::<String>(),
            "f345a219da005ebe9c1a1eaad97bbf38a10c8473e41d0af7fb617caa0c6aa722"
        );
    }
}
