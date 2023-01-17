use librypt_hash::{Hash, HashFn};

use crate::keccak::Keccak;

pub struct Sha3_512 {
    keccak: Keccak<72, 0x06>,
}

impl HashFn<72, 64> for Sha3_512 {
    fn new() -> Self {
        Self {
            keccak: <_ as HashFn<72, 64>>::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        <_ as HashFn<72, 64>>::update(&mut self.keccak, data);
    }

    fn finalize(self) -> Hash<64> {
        self.keccak.finalize()
    }

    fn finalize_reset(&mut self) -> Hash<64> {
        self.keccak.finalize_reset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::ToHex;

    #[test]
    fn test_sha3_512() {
        let hash = Sha3_512::hash(b"Hello, world!");

        assert_eq!(
            hash.encode_hex::<String>(),
            "8e47f1185ffd014d238fabd02a1a32defe698cbf38c037a90e3c0a0a32370fb52cbd641250508502295fcabcbf676c09470b27443868c8e5f70e26dc337288af"
        );
    }
}
