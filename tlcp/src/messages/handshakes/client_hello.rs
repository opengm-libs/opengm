use crate::messages::{HandshakeMsgType, HANDSHAKD_HEADER_LENGTH};
use opengm_crypto::cryptobyte::{Builder, Parser, parser::AsParser};
use crate::Result;

const MSG_TYPE:HandshakeMsgType = HandshakeMsgType::ClientHello;

// pub(crate) enum ClientHelloMessage<'a>{
//     Owned(ClientHelloMsg),
//     Borrowed(ClientHelloMsgRef<'a>),
// }

#[derive(Debug, PartialEq, Eq)]
pub struct ClientHelloMsgOwned {
    pub raw: Option<Vec<u8>>,
    pub vers: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>, // 0-32bytes
    pub cipher_suite_ids: Vec<u16>,
    pub compression_methods: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ClientHelloMsgBorrowed<'a> {
    pub raw: &'a [u8],

    pub vers: u16,
    pub random: &'a [u8],
    pub session_id: &'a [u8],
    pub cipher_suite_ids: Vec<u16>,
    pub compression_methods: Vec<u8>,
}

// impl<'a> ClientHelloMessage<'a> {
//     #[inline]
//     fn handshake_type() -> HandshakeMsgType {
//         MSG_TYPE
//     }

//     pub fn bytes(&mut self) -> Result<&[u8]> {
//         match self {
//             ClientHelloMessage::Owned(owned) => owned.bytes(),
//             ClientHelloMessage::Borrowed(borrowed) => borrowed.bytes(),
//         }
//     }

//     pub fn parse(data: &'a [u8]) -> Result<Self>{
//         Ok(ClientHelloMessage::Borrowed(
//             ClientHelloMsgRef::parse(data)
//             .ok_or(Error::InvalidHandshakeMsg)?
//         ))
//     }
// }


impl ClientHelloMsgOwned{
    #[inline]
    fn handshake_type() -> HandshakeMsgType {
        MSG_TYPE
    }

    pub fn bytes(&mut self) -> Result<&[u8]> {
        if self.raw.is_some() {
            Ok(self.raw.as_ref().unwrap())
        } else {
            let mut b = Builder::new(Vec::with_capacity(128));
            b.add_u8(MSG_TYPE.into());
            b.add_u24_length_prefixed(|b| {
                b.add_u16(self.vers);

                b.add_bytes(self.random.as_slice());

                b.add_u8_length_prefixed(|b| {
                    b.add_bytes(self.session_id.as_slice());
                });

                b.add_u16_length_prefixed(|b| {
                    for suite in &self.cipher_suite_ids {
                        b.add_u16(*suite);
                    }
                });

                b.add_u8_length_prefixed(|b| {
                    b.add_bytes(self.compression_methods.as_slice());
                });
            });
            self.raw = Some(b.take()?);
            Ok(self.raw.as_ref().unwrap())
        }
    }
}

impl<'a> ClientHelloMsgBorrowed<'a> {

    pub fn bytes(&self) -> Result<&[u8]> {
        Ok(self.raw)
    }

    // Move to ClientHelloMsg
    pub fn to_owned(self) -> ClientHelloMsgOwned {
        let mut owned = ClientHelloMsgOwned {
            raw: Some(Vec::from(self.raw)),
            vers: self.vers,
            random: [0; 32],
            session_id: Vec::from(self.session_id),
            cipher_suite_ids: self.cipher_suite_ids,
            compression_methods: self.compression_methods,
        };
        owned.random.copy_from_slice(self.random);
        owned
    }
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < HANDSHAKD_HEADER_LENGTH {
            return None;
        }

        let mut parser = Parser::new(data);
        if parser.read_u8()? != u8::from(MSG_TYPE) {
            return None;
        }

        let mut inner_parser = parser.read_u24_length_prefixed()?.as_parser();
        let vers = inner_parser.read_u16()?;
        let random = inner_parser.read_bytes(32)?;
        let session_id = inner_parser.read_u8_length_prefixed()?;

        let mut cipher_suite_ids_parser = inner_parser.read_u16_length_prefixed()?.as_parser();
        let mut compression_methods_parser = inner_parser.read_u8_length_prefixed()?.as_parser();
        let mut cipher_suite_ids = Vec::with_capacity(cipher_suite_ids_parser.len() / 2);
        let mut compression_methods = Vec::with_capacity(compression_methods_parser.len() / 2);

        loop {
            let id = cipher_suite_ids_parser.read_u16();
            match id {
                Some(id) => cipher_suite_ids.push(id),
                None => break,
            }
        }

        loop {
            let method = compression_methods_parser.read_u8();
            match method {
                Some(method) => compression_methods.push(method),
                None => break,
            }
        }

        Some(ClientHelloMsgBorrowed {
            raw: &data[..parser.bytes_read()],
            vers,
            random,
            session_id,
            cipher_suite_ids,
            compression_methods: compression_methods,
        })
    }
}


#[cfg(test)]
mod tests {
    use crate::consts::{COMPRESSION_NONE, TLCP_ECC_SM4_CBC_SM3, TLCP_ECC_SM4_GCM_SM3, VERSION_TLCP};
    
    use super::*;

    #[test]
    fn test_clienthello() {
        let mut client_hello = ClientHelloMsgOwned {
            raw: None,
            vers: VERSION_TLCP,
            random: [1; 32],
            session_id: vec![2; 32],
            cipher_suite_ids: vec![TLCP_ECC_SM4_CBC_SM3, TLCP_ECC_SM4_GCM_SM3],
            compression_methods: vec![COMPRESSION_NONE],
        };

        let b = client_hello.bytes().unwrap();
        let client_hello2 = ClientHelloMsgBorrowed::parse(b).unwrap().to_owned();
        assert_eq!(client_hello, client_hello2);
    }
}