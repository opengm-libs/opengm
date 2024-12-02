
use crate::messages::HandshakeMsgType;
use opengm_crypto::cryptobyte::{Builder, Parser, parser::AsParser};
use crate::Result;

const MSG_TYPE:HandshakeMsgType = HandshakeMsgType::ServerHello;
//TODO: Extensions
#[derive(Debug, PartialEq, Eq)]
pub struct ServerHelloMsgOwned {
    pub raw: Option<Vec<u8>>,

    pub vers: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite_id: u16,
    pub compression_method: u8,
}

impl ServerHelloMsgOwned {
    #[inline]
    fn handshake_type() -> HandshakeMsgType {
        MSG_TYPE
    }

    pub fn bytes(&mut self) -> Result<&[u8]> {
        if self.raw.is_some() {
            Ok(self.raw.as_ref().unwrap())
        } else {
            let mut b = Builder::new(Vec::with_capacity(128));
            b.add_u8(Self::handshake_type().into());
            b.add_u24_length_prefixed(|b| {
                b.add_u16(self.vers);

                b.add_bytes(self.random.as_slice());

                b.add_u8_length_prefixed(|b| {
                    b.add_bytes(self.session_id.as_slice());
                });
                b.add_u16(self.cipher_suite_id);
                b.add_u8(self.compression_method);
            });
            self.raw = Some(b.take()?);
            Ok(self.raw.as_ref().unwrap())
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
//TODO: Extensions
pub struct ServerHelloMsgBorrowed<'a> {
    pub raw: &'a [u8],

    pub vers: u16,
    pub random: &'a [u8],
    pub session_id: &'a [u8],
    pub cipher_suite_id: u16,
    pub compression_method: u8,
}

impl<'a> ServerHelloMsgBorrowed<'a> {
    #[inline]
    fn handshake_type() -> HandshakeMsgType {
        MSG_TYPE
    }

    // Always return Ok(.) for consistency with non-ref.
    #[inline]
    pub fn bytes(&mut self) -> Result<&[u8]> {
        Ok(self.raw)
    }

    // Move to ClientHelloMsg
    pub fn to_owned(self) -> ServerHelloMsgOwned {
        let mut owned = ServerHelloMsgOwned {
            raw: Some(Vec::from(self.raw)),
            vers: self.vers,
            random: [0; 32],
            session_id: Vec::from(self.session_id),
            cipher_suite_id: self.cipher_suite_id,
            compression_method: self.compression_method,
        };
        owned.random.copy_from_slice(self.random);
        owned
    }

    pub fn parse(data: &'a [u8]) -> Option<ServerHelloMsgBorrowed<'a>> {
        let mut parser = Parser::new(data);
        if parser.read_u8()? != u8::from(Self::handshake_type()) {
            return None;
        }

        let mut inner_parser = parser.read_u24_length_prefixed()?.as_parser();
        let vers = inner_parser.read_u16()?;
        let random = inner_parser.read_bytes(32)?;
        let session_id = inner_parser.read_u8_length_prefixed()?;
        let cipher_suite_id = inner_parser.read_u16()?;
        let compression_methods = inner_parser.read_u8()?;

        debug_assert!(parser.bytes_read() == data.len());
        Some(ServerHelloMsgBorrowed {
            raw: &data[..parser.bytes_read()],
            vers,
            random,
            session_id,
            cipher_suite_id,
            compression_method: compression_methods,
        })
    }
}


#[cfg(test)]
mod tests {
    use crate::consts::{COMPRESSION_NONE, TLCP_ECC_SM4_CBC_SM3, VERSION_TLCP};
    use super::*;

    #[test]
    fn test_serverhello() {
        let mut server_hello = ServerHelloMsgOwned {
            raw: None,
            vers: VERSION_TLCP,
            random: [1; 32],
            session_id: vec![2; 32],
            cipher_suite_id: TLCP_ECC_SM4_CBC_SM3,
            compression_method: COMPRESSION_NONE,
        };

        let b = server_hello.bytes().unwrap();
        let server_hello2 = ServerHelloMsgBorrowed::parse(b).unwrap().to_owned();
        assert_eq!(server_hello, server_hello2);
    }

}