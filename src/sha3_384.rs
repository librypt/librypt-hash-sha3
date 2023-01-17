use librypt_hash::{Hash, HashFn};

use crate::keccak::Keccak;

pub struct Sha3_384 {
    keccak: Keccak<104, 0x06>,
}

impl HashFn<104, 48> for Sha3_384 {
    fn new() -> Self {
        Self {
            keccak: <_ as HashFn<104, 48>>::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        <_ as HashFn<104, 48>>::update(&mut self.keccak, data);
    }

    fn finalize(self) -> Hash<48> {
        self.keccak.finalize()
    }

    fn finalize_reset(&mut self) -> Hash<48> {
        self.keccak.finalize_reset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::ToHex;

    #[test]
    fn test_sha3_384() {
        let hash = Sha3_384::hash(b"Hello, world!");

        assert_eq!(
            hash.encode_hex::<String>(),
            "6ba9ea268965916f5937228dde678c202f9fe756a87d8b1b7362869583a45901fd1a27289d72fc0e3ff48b1b78827d3a"
        );
    }
}
