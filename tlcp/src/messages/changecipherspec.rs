#[derive(Debug)]
pub struct ChangeCipherSpecMsg([u8; 1]);

impl ChangeCipherSpecMsg {
    pub fn new() -> Self {
        Self([1])
    }
    pub fn bytes(&mut self) -> [u8; 1] {
        [1]
    }

    pub fn try_from(b: &[u8]) -> Option<Self> {
        if b.len() == 1 && b[0] == 1 {
            Some(Self::new())
        } else {
            None
        }
    }
}
