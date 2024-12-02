use crate::messages::HandshakeMsgType;

const MSG_TYPE:HandshakeMsgType = HandshakeMsgType::ServerHelloDone;

#[derive(Debug)]
pub struct ServerHelloDoneMsg([u8; 4]);

impl Default for ServerHelloDoneMsg {
    fn default() -> Self {
        ServerHelloDoneMsg([u8::from(HandshakeMsgType::ServerHelloDone), 0, 0, 0])
    }
}

impl ServerHelloDoneMsg {
    #[inline]
    fn handshake_type() -> HandshakeMsgType {
        MSG_TYPE
    }

    pub fn new() -> ServerHelloDoneMsg {
        ServerHelloDoneMsg::default()
    }
    pub fn bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != 4 || data[0] != u8::from(Self::handshake_type()) || data[1] != 0 || data[2] != 0 || data[3] != 0 {
            None
        } else {
            Some(ServerHelloDoneMsg::default())
        }
    }
}