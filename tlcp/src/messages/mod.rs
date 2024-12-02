mod alert;
mod changecipherspec;
mod handshakes;
pub use alert::*;
pub use changecipherspec::*;
pub use handshakes::*;

// use crate::encoding::sm2::publickey::ASN1Decode;

/*
      Client                                               Server

      ClientHello                  -------->
                                                      ServerHello
                                                     Certificate*
                                               ServerKeyExchange*
                                              CertificateRequest*
                                   <--------      ServerHelloDone
      Certificate*
      ClientKeyExchange
      CertificateVerify*
      [ChangeCipherSpec]
      Finished                     -------->
                                               [ChangeCipherSpec]
                                   <--------             Finished
      Application Data             <------->     Application Data
*/

// TLS handshake message types.
#[derive(Copy, Clone)]
pub enum HandshakeMsgType {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
    CertificateStatus = 22,
    KeyUpdate = 24,
    NextProtocol = 67,
    MessageHash = 254,

    UnknownHandShakeMsgType = 255,// ?
}

// handshake message: header(type(1) + length(3)) + body(length).
const HANDSHAKD_HEADER_LENGTH: usize = 4;
impl From<HandshakeMsgType> for u8 {
    fn from(value: HandshakeMsgType) -> Self {
        value as u8
    }
}

impl TryFrom<u8> for HandshakeMsgType {
    type Error = crate::Error;

    fn try_from(v: u8) -> std::result::Result<Self, Self::Error> {
        match v {
            0 => Ok(HandshakeMsgType::HelloRequest),
            1 => Ok(HandshakeMsgType::ClientHello),
            2 => Ok(HandshakeMsgType::ServerHello),
            4 => Ok(HandshakeMsgType::NewSessionTicket),
            5 => Ok(HandshakeMsgType::EndOfEarlyData),
            8 => Ok(HandshakeMsgType::EncryptedExtensions),
            11 => Ok(HandshakeMsgType::Certificate),
            12 => Ok(HandshakeMsgType::ServerKeyExchange),
            13 => Ok(HandshakeMsgType::CertificateRequest),
            14 => Ok(HandshakeMsgType::ServerHelloDone),
            15 => Ok(HandshakeMsgType::CertificateVerify),
            16 => Ok(HandshakeMsgType::ClientKeyExchange),
            20 => Ok(HandshakeMsgType::Finished),
            22 => Ok(HandshakeMsgType::CertificateStatus),
            24 => Ok(HandshakeMsgType::KeyUpdate),
            67 => Ok(HandshakeMsgType::NextProtocol),
            254 => Ok(HandshakeMsgType::MessageHash),
            _ => Err(Self::Error::UnknownHandShakeMsgType(v)),
        }
    }
}
