use opengm_crypto::cryptobyte::Parser;
use crate::messages::HandshakeMsgType;
use crate::Result;

const MSG_TYPE: HandshakeMsgType = HandshakeMsgType::Finished;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct FinishedMsgOwned {
    raw: Option<Vec<u8>>,
    verify_data: [u8; 12],
}

impl FinishedMsgOwned {
    #[inline]
    fn handshake_type() -> HandshakeMsgType {
        HandshakeMsgType::Finished
    }

    pub fn new(data: &[u8]) -> Self {
        Self {
            raw: None,
            verify_data: data[..12].try_into().unwrap(),
        }
    }

    pub fn bytes(&mut self) -> Result<&[u8]> {
        if self.raw.is_none() {
            self.raw = Some(Vec::new());
        }
        let mut raw = Vec::with_capacity(16);
        raw.push(u8::from(Self::handshake_type()));
        raw.push(0);
        raw.push(0);
        raw.push(12);
        raw.extend_from_slice(&self.verify_data);
        self.raw = Some(raw);

        Ok(self.raw.as_ref().unwrap())
    }
}

#[derive(Debug, Default)]
pub struct FinishedMsgBorrowed<'a> {
    raw: &'a [u8],
    pub verify_data: &'a [u8], // always has length 12.
}

impl<'a> FinishedMsgBorrowed<'a> {
    #[inline]
    fn handshake_type() -> HandshakeMsgType {
        HandshakeMsgType::Finished
    }

    pub fn bytes(&self) -> &[u8] {
        return  self.raw;
    }

    pub fn to_owned(&self) -> FinishedMsgOwned {
        FinishedMsgOwned {
            raw: Some(self.raw.to_owned()),
            verify_data: self
                .verify_data
                .try_into()
                .expect("FinishedMsgRef has a invalid length of verify data"),
        }
    }

    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let mut parser = Parser::new(data);
        if parser.read_u8()? != u8::from(Self::handshake_type()) {
            return None;
        }

        let verify_data = parser.read_u24_length_prefixed()?;
        Some(FinishedMsgBorrowed {
            raw: data,
            verify_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finished() {
        let mut msg = FinishedMsgOwned {
            raw: None,
            verify_data: [1; 12],
        };

        let b = msg.bytes().unwrap();
        let msg2 = FinishedMsgBorrowed::parse(b).unwrap().to_owned();
        assert_eq!(msg, msg2);
    }
}
