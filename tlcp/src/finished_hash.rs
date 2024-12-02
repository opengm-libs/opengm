use crate::traits::Hash;

pub struct FinishedHash<H: Hash<DIGEST_SIZE> + Default, const DIGEST_SIZE: usize> {
    // version: u16,
    client: H,
    server: H,

    // TLCP，对前面的所有消息的SM3值做签名。所以不用保存
    // 但是，GMSSL实现的是对前面所有消息做签名，因此也需要一个buffer
    buffer: Vec<u8>,
}

impl<H: Hash<DIGEST_SIZE> + Default, const DIGEST_SIZE: usize> FinishedHash<H, DIGEST_SIZE> {
    pub fn new() -> Self {
        FinishedHash {
            client: H::default(),
            server: H::default(),
            buffer: Vec::new(),
        }
    }

    pub fn write(&mut self, data: &[u8]) {
        self.client.write(data);
        self.server.write(data);
    }
    pub fn sum(&self) -> [u8; DIGEST_SIZE] {
        self.client.sum()
    }
}
