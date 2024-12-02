use crate::messages::HandshakeMsgType;
use opengm_crypto::cryptobyte::Parser;
use crate::Result;


const MSG_TYPE:HandshakeMsgType = HandshakeMsgType::ServerKeyExchange;

// - For ECC cipher suite:
//  key ::= SEQUENCE{
//      r INTEGER,
//      s INTEGER
//  }
#[derive(Debug, Default,PartialEq, Eq)]
pub struct ServerKeyExchangeMsgOwned {
    pub raw: Option<Vec<u8>>,
    pub key: Vec<u8>,
}

/*
Note that TLCP and TLS 1.0, 1.1
struct {
    opaque signature<0..2^16-1>;
 } DigitallySigned;

and for TLS 1.2 1.3
struct {
    SignatureAndHashAlgorithm algorithm;
    opaque signature<0..2^16-1>;
 } DigitallySigned;
*/

/*
enum {ECDHE，ECC,IBSDH,IBC,RSA} KeyExchangeAlgorithm;
struct {
    select (KeyExchangeAlgorithm){
        case ECDHE:
            ServerECDHEParams params;
            digitally-signed struct {
                opaque client_random[32];
                opaque server_random[32];
                ServerECDHEParams params;
            } signed_params;
        case ECC:
            digitally-signed struct {
                opaque client_random[32];
                opaque server_random[32];
                opaque ASN.1Cert<1..2^24-1>;
            } signed_params;
        case IBSDH:
            ServerIBSDHParams params;
            digitally-signed struct {
                opaque client_random[32];
                opaque server_random[32];
                ServerIBSDHParams params;
            } signed_params;
        case IBC:
            digitally-signed struct {
                opaque client_random[32];
                opaque server_random[32];
                opaque ibc_id<1..2^16-1>;
            } signed_params;
        case RSA:
            digitally-signed struct {
                opaque client_random[32];
                opaque server_random[32];
                opaque ASN.1Cert<1..2^24-1>;
            } signed_params;
    }
} ServerKeyExchange;
*/
impl ServerKeyExchangeMsgOwned {
    #[inline]
    fn handshake_type() -> HandshakeMsgType {
        HandshakeMsgType::ServerKeyExchange
    }

    pub fn bytes(&mut self) -> Result<&[u8]> {
        if self.raw.is_some() {
            Ok(self.raw.as_ref().unwrap())
        } else {
            // construct the raw bytes directly without Builder.
            let mut raw = Vec::with_capacity(4 + self.key.len());
            raw.push(u8::from(Self::handshake_type()));
            raw.push((self.key.len() >> 16) as u8);
            raw.push((self.key.len() >> 8) as u8);
            raw.push(self.key.len() as u8);
            raw.extend_from_slice(&self.key);
            self.raw = Some(raw);

            Ok(self.raw.as_ref().unwrap())
        }
    }
}
#[derive(Debug, Default)]
pub struct ServerKeyExchangeMsgBorrowed<'a> {
    pub raw: &'a [u8],
    pub key: &'a [u8],
}

impl<'a> ServerKeyExchangeMsgBorrowed<'a> {
    #[inline]
    fn handshake_type() -> HandshakeMsgType {
        HandshakeMsgType::ServerKeyExchange
    }

    pub fn to_owned(self) -> ServerKeyExchangeMsgOwned {
        ServerKeyExchangeMsgOwned {
            raw: Some(self.raw.to_owned()),
            key: self.key.to_owned(),
        }
    }

    pub fn parse(v: &'a [u8]) -> Option<Self> {
        let mut parser = Parser::new(v);
        if parser.read_u8()? != u8::from(Self::handshake_type()) {
            return None;
        }
        let key = parser.read_u24_length_prefixed()?;
        Some(ServerKeyExchangeMsgBorrowed { raw: v, key })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_key_exchange() {
        let mut ske = ServerKeyExchangeMsgOwned {
            raw: None,
            key: vec![4; 10],
        };

        let b = ske.bytes().unwrap();
        let ske2 = ServerKeyExchangeMsgBorrowed::parse(b).unwrap().to_owned();
        assert_eq!(ske, ske2);
    }

}
