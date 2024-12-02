
use core::borrow;

use crate::messages::{HandshakeMsgType, HANDSHAKD_HEADER_LENGTH};
use opengm_crypto::cryptobyte::{Builder, Parser, parser::AsParser};
use crate::{Result, Error};

use super::parse_handshake_msg_header;

const MSG_TYPE:HandshakeMsgType = HandshakeMsgType::ClientKeyExchange;

#[derive(Debug, Default)]
pub struct ClientKeyExchangeMsgOwned {
    raw: Option<Vec<u8>>,
    ciphertext: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct ClientKeyExchangeMsgBorrowed<'a> {
    raw:  &'a [u8],
    pub ciphertext:  &'a [u8],
}

impl ClientKeyExchangeMsgOwned {
    pub fn new(ciphertext: Vec<u8>) -> Self {
        Self { raw: None, ciphertext: ciphertext }
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>> {
        if self.raw.is_none() {
            self.raw = Some(Vec::new());
        }

        let mut b = Builder::new(Vec::new());
        b.add_u8(HandshakeMsgType::ClientKeyExchange.into());
        b.add_u24_length_prefixed(|b| {
            b.add_u16_length_prefixed(|b| {
                b.add_bytes(&self.ciphertext);
            });
        });
        Ok(b.take()?)
    }
}





impl<'a> ClientKeyExchangeMsgBorrowed<'a> {
    
    pub fn bytes(&self) -> Result<&[u8]> {
        Ok(self.raw)
    }

    // Move to ClientHelloMsg
    pub fn to_owned(self) -> ClientKeyExchangeMsgOwned {
        ClientKeyExchangeMsgOwned {
            raw: None,
            ciphertext: self.ciphertext.to_owned(),
        }
    }

    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if let Some((msg_type, body)) = parse_handshake_msg_header(data){
            if msg_type != HandshakeMsgType::ClientKeyExchange.into(){
                return None
            }
            let ciphertext = Parser::new(body).read_u16_length_prefixed()?;
            Some(ClientKeyExchangeMsgBorrowed{
                raw: data,
                ciphertext,
            })
        }else{
            None
        }
    }
}
