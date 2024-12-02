use std::any::Any;

use num::BigInt;
use opengm_crypto::sm2;
use opengm_crypto::cryptobyte::{asn1::*, oid::OidSignatureSM2WithSM3, sm2::*, Parser, Tag};
use super::errors::{Error, Result};


pub enum SignatureAlgorithm {
	UnknownSignatureAlgorithm,
	SHA1WithRSA, // Only supported for signing, not verification.
	SHA256WithRSA,
	SHA384WithRSA,
	SHA512WithRSA,
	ECDSAWithSHA1, // Only supported for signing, not verification.
	ECDSAWithSHA256,
	ECDSAWithSHA384,
	ECDSAWithSHA512,
	SHA256WithRSAPSS,
	SHA384WithRSAPSS,
	SHA512WithRSAPSS,
	PureEd25519,
}


#[derive(Default)]
pub struct ASN1Certificate<'a>{
    raw: &'a [u8],
    tbs_certificate: ASN1TBSCertificate<'a>,
    signature_algorithm: AlgorithmIdentifier<'a>,
    signature: BitString,
}

#[derive(Default)]
pub struct ASN1TBSCertificate<'a>{
    raw: &'a [u8],
    // optional,explicit,default:0,tag:0
	version       :i32,
	
    serial_number   : BigInt,
	
    signature_algorithm: AlgorithmIdentifier<'a>,

	// issuer:             RawObject,

	// Validity  :         validity,
	// Subject            asn1.RawValue
	// PublicKey          publicKeyInfo
	// UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	// SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	// Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

// pub struct Validity{
//     not_before: asn1.Time,

// }

#[derive(Default)]
pub struct AlgorithmIdentifier<'a>{
    algorithm: ObjectIdentifier,
    parameters: &'a [u8],
}

impl<'a> AlgorithmIdentifier<'a>{

}

pub fn parse_asn1_certificate(der: &[u8])-> Option<ASN1Certificate>{
    let mut certificate = Parser::new(der);
    let mut _tbs_certificate = certificate.read_asn1_sequence()?;
    let mut _signature_algorithm = certificate.read_asn1_sequence()?;
    let mut _signature_value = certificate.read_asn1_bit_string()?;

    let res = ASN1Certificate::default();
    Some(res)
}

fn parse_asn1_tbs_certificate<'a>(_parser: &mut Parser<'a>) -> Option<ASN1TBSCertificate<'a>>{
    todo!()
}

// 从证书中解析公钥.
pub fn parse_asn1_sm2_public(der: &[u8]) -> Option<sm2::PublicKey>{

    let mut parser = Parser::new(der);
    let mut certificate = parser.read_asn1_sequence()?;
    let mut tbs_certificate = certificate.read_asn1_sequence()?;

    // version
    if tbs_certificate.peek_tag() == Some(Tag(0xa0)){
        tbs_certificate.read_asn1_object()?;
    }

    // serial number
    let _serial_number = tbs_certificate.read_asn1_bigint()?;
    let _algorithm_identifier = tbs_certificate.read_asn1_sequence();

    let _issuer = tbs_certificate.read_asn1_sequence()?;

    let _validity = tbs_certificate.read_asn1_sequence()?;
    let _subject = tbs_certificate.read_asn1_sequence()?;

    let mut subject_public_key_info = tbs_certificate.read_asn1_sequence()?;
    let mut algorithm_identifier= subject_public_key_info.read_asn1_sequence()?;
    let algorithm = algorithm_identifier.read_asn1_object_identifier()?;
    if algorithm != OidSignatureSM2WithSM3{
        return None;
    }

    // public key:= BIT STRING, for sm2, key = 04 || x || y etc.
    let subject_public_key = subject_public_key_info.read_asn1_bit_string()?;
    let public_key = Parser::new(&subject_public_key.bytes).decode_sm2_public_key()?;   
    Some(public_key)
}



// 从证书中解析公钥.
pub fn parse_asn1_sm2_signature(der: &[u8]) -> Option<sm2::Signature>{
    let mut parser = Parser::new(der);
    let mut certificate = parser.read_asn1_sequence()?;
    
    // tbsCertificates
    let _ = certificate.read_asn1_sequence()?;
    // AlgorithmIdentifier
    let _ = certificate.read_asn1_sequence()?;
    let mut signature = certificate.read_asn1_sequence()?;
    // assume sm2
    Some(signature.decode_sm2_signature()?)
}


pub fn verify(public_key: &dyn Any, data: &[u8], sig: &dyn Any) ->Result<bool> {
    if let Some(public_key) = public_key.downcast_ref::<sm2::PublicKey>() {
        if let Some(sig) = sig.downcast_ref::<sm2::Signature>(){
            if let Ok(e) = data.try_into(){
                return Ok(sm2::verify(e, public_key, sig));
            }
        }
    }
    Err(Error::SM2Verify)
}



#[cfg(test)]
mod tests {
    
    #[derive(Debug)]
    struct TypeA<'a> {
        a: &'a [i32],
        b: &'a [i32],
    }
    #[test]
    fn test_1() {
        let data = [0;100];
        let a = TypeA{
            a: &data[1..2],
            b: &data[3..4],
        };

        let b = TypeA{
            a: &data[3..4],
            b: &data[3..5],
        };
        println!("{:?}", a);
        println!("{:?}", b);
    }
}
