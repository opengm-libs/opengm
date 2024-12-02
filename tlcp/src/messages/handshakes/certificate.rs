use crate::messages::HandshakeMsgType;
use opengm_crypto::cryptobyte::{Builder, Parser, parser::AsParser};
use crate::{Result, Error};

const MSG_TYPE:HandshakeMsgType = HandshakeMsgType::Certificate;


#[derive(Debug, Default, PartialEq, Eq)]
pub struct CertificateMsgOwned {
    pub raw: Option<Vec<u8>>,
    pub certificates: Vec<Vec<u8>>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct CertificateMsgBorrowed<'a> {
    pub raw: &'a [u8],
    pub certificates: Vec<&'a [u8]>,
}

impl CertificateMsgOwned {
    #[inline]
    fn handshake_type() -> HandshakeMsgType {
        MSG_TYPE
    }

    pub fn bytes(&mut self) -> Result<&[u8]> {
        if self.raw.is_some() {
            Ok(self.raw.as_ref().unwrap())
        } else {
            // body总长度 = 证书消息长度3个字节 +  3 * 证书个数 + 所有证书长度
            let mut body_length = 3 + 3 * self.certificates.len();
            for cert in &self.certificates {
                body_length += cert.len();
            }
            let mut raw = Vec::with_capacity(4 + body_length);
            raw.push(u8::from(Self::handshake_type()));
            raw.push((body_length >> 16) as u8);
            raw.push((body_length >> 8) as u8);
            raw.push((body_length >> 0) as u8);

            let certificates_length = body_length - 3;
            raw.push((certificates_length >> 16) as u8);
            raw.push((certificates_length >> 8) as u8);
            raw.push((certificates_length >> 0) as u8);

            for cert in &self.certificates {
                let cert_len = cert.len();
                raw.push((cert_len >> 16) as u8);
                raw.push((cert_len >> 8) as u8);
                raw.push((cert_len >> 0) as u8);
                for i in cert {
                    raw.push(*i);
                }
            }
            self.raw = Some(raw);
            Ok(self.raw.as_ref().unwrap())
        }
    }
}

impl<'a> CertificateMsgBorrowed<'a> {
    #[inline]
    fn handshake_type() -> HandshakeMsgType {
        HandshakeMsgType::Certificate
    }

    // Move to ClientHelloMsg
    pub fn to_owned(self) -> CertificateMsgOwned {
        let mut certificates = Vec::with_capacity(self.certificates.len());
        for cert in self.certificates {
            certificates.push(cert.to_owned());
        }
        CertificateMsgOwned {
            raw: Some(self.raw.to_owned()),
            certificates,
        }
    }
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 7 {
            return None;
        }

        let mut parser = Parser::new(data);
        if parser.read_u8()? != u8::from(Self::handshake_type()) {
            return None;
        }

        let body_len = parser.read_u24()? as usize;
        if body_len + 4 > data.len() {
            return None;
        }

        let mut inner_parser = parser.read_u24_length_prefixed()?.as_parser();
        let mut certificates = Vec::with_capacity(4);
        while inner_parser.len() > 0 {
            certificates.push(inner_parser.read_u24_length_prefixed()?);
        }

        Some(CertificateMsgBorrowed {
            raw: &data[..parser.bytes_read()],
            certificates,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::consts::{COMPRESSION_NONE, TLCP_ECC_SM4_CBC_SM3, TLCP_ECC_SM4_GCM_SM3, VERSION_TLCP};
    use hex_literal::hex;

    use super::*;

    #[test]
    fn test_certificates() {
        let mut certificates = CertificateMsgOwned {
            raw: None,
            certificates: vec![vec![1; 10], vec![2; 10], vec![3; 10], vec![4; 10]],
        };

        let b = certificates.bytes().unwrap();
        let certificates2 = CertificateMsgBorrowed::parse(b).unwrap().to_owned();
        assert_eq!(certificates, certificates2);
    }
}