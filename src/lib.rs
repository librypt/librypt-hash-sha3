#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

pub mod keccak;
mod sha3_224;
mod sha3_256;
mod sha3_384;
mod sha3_512;
mod shake128;
mod shake256;

pub use sha3_224::Sha3_224;
pub use sha3_256::Sha3_256;
pub use sha3_384::Sha3_384;
pub use sha3_512::Sha3_512;
pub use shake128::Shake128;
pub use shake256::Shake256;
