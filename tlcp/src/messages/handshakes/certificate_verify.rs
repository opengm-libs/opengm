use crate::messages::HandshakeMsgType;
const MSG_TYPE:HandshakeMsgType = HandshakeMsgType::CertificateVerify;

#[derive(Debug, Default)]
pub struct CertificateVerifyMsg {}