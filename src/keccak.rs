use librypt_hash::{Hash, HashFn};

/// Keccak sponge function.
///
/// NOTE: This implementation only supports a permutation width of 1600.
pub struct Keccak<const BLOCK_SIZE: usize, const SUFFIX: u8> {
    state: [u8; 200],
    buffer: (usize, [u8; BLOCK_SIZE]),
}

impl<const BLOCK_SIZE: usize, const SUFFIX: u8> Keccak<BLOCK_SIZE, SUFFIX> {
    fn rol64(a: u64, n: u64) -> u64 {
        a.wrapping_shr(64u32.wrapping_sub(n as u32 % 64))
            .wrapping_add(a.wrapping_shl(n as u32 % 64))
    }

    fn compute(&mut self) {
        let mut lanes = [[0u64; 5]; 5];

        for x in 0..5 {
            for y in 0..5 {
                let i = (y * 5 + x) * 8;
                lanes[x][y] = u64::from_le_bytes(self.state[i..i + 8].try_into().unwrap());
            }
        }

        let mut r = 1;

        for _ in 0..24 {
            let c: [u64; 5] = core::array::from_fn(|x| {
                lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4]
            });

            let d: [u64; 5] =
                core::array::from_fn(|x| c[(x + 4) % 5] ^ Self::rol64(c[(x + 1) % 5], 1));

            for x in 0..5 {
                for y in 0..5 {
                    lanes[x][y] ^= d[x];
                }
            }

            let mut pos = (1, 0);
            let mut current = lanes[pos.0][pos.1];

            for t in 0..24 {
                pos = (pos.1, (2 * pos.0 + 3 * pos.1) % 5);

                (current, lanes[pos.0][pos.1]) = (
                    lanes[pos.0][pos.1],
                    Self::rol64(current, (t + 1) * (t + 2) / 2),
                );
            }

            for y in 0..5 {
                let t: [u64; 5] = core::array::from_fn(|x| lanes[x][y]);

                for x in 0..5 {
                    lanes[x][y] = t[x] ^ ((!t[(x + 1) % 5]) & t[(x + 2) % 5]);
                }
            }

            for j in 0..7 {
                r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256;

                if r & 2 != 0 {
                    lanes[0][0] ^= 1 << ((1 << j) - 1);
                }
            }
        }

        for x in 0..5 {
            for y in 0..5 {
                let i = (y * 5 + x) * 8;
                self.state[i..i + 8].copy_from_slice(&lanes[x][y].to_le_bytes());
            }
        }
    }

    fn compute_padded(&mut self) {
        self.buffer.1[self.buffer.0] = SUFFIX;
        self.buffer.0 += 1;

        if self.buffer.0 == BLOCK_SIZE - 1 {
            for i in self.buffer.0..BLOCK_SIZE {
                self.buffer.1[i] = 0;
            }

            for i in 0..BLOCK_SIZE {
                self.state[i] ^= self.buffer.1[i];
            }

            self.compute();

            self.buffer.0 = 0;
        }

        for i in self.buffer.0..BLOCK_SIZE {
            self.buffer.1[i] = 0;
        }

        self.buffer.1[BLOCK_SIZE - 1] = 0x80;

        for i in 0..BLOCK_SIZE {
            self.state[i] ^= self.buffer.1[i];
        }

        self.compute();
    }
}

impl<const BLOCK_SIZE: usize, const OUTPUT_SIZE: usize, const SUFFIX: u8>
    HashFn<BLOCK_SIZE, OUTPUT_SIZE> for Keccak<BLOCK_SIZE, SUFFIX>
{
    fn new() -> Self {
        Self {
            state: [0u8; 200],
            buffer: (0, [0u8; BLOCK_SIZE]),
        }
    }

    fn update(&mut self, data: &[u8]) {
        for b in data {
            self.buffer.1[self.buffer.0] = *b;
            self.buffer.0 += 1;

            if self.buffer.0 == BLOCK_SIZE {
                for i in 0..BLOCK_SIZE {
                    self.state[i] ^= self.buffer.1[i];
                }

                self.compute();

                self.buffer.0 = 0;
            }
        }
    }

    fn finalize(mut self) -> Hash<OUTPUT_SIZE> {
        self.compute_padded();

        let mut total = 0;
        let mut hash = [0u8; OUTPUT_SIZE];

        while total < OUTPUT_SIZE {
            let block = (OUTPUT_SIZE - total).min(BLOCK_SIZE);

            hash[total..block].copy_from_slice(&self.state[..block]);
            total += block;

            if total < OUTPUT_SIZE {
                self.compute();
            }
        }

        hash
    }

    fn finalize_reset(&mut self) -> Hash<OUTPUT_SIZE> {
        self.compute_padded();

        let mut total = 0;
        let mut hash = [0u8; OUTPUT_SIZE];

        while total < OUTPUT_SIZE {
            let block = (OUTPUT_SIZE - total).min(BLOCK_SIZE);

            hash[total..block].copy_from_slice(&self.state[..block]);
            total += block;

            if total < OUTPUT_SIZE {
                self.compute();
            }
        }

        // reset state
        self.state = [0u8; 200];
        self.buffer = (0, [0u8; BLOCK_SIZE]);

        hash
    }
}
