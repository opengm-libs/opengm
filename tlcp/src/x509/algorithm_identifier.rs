use super::oid::*;

#[derive(asn1::Asn1Write, PartialEq, Debug, Eq)]
pub struct AlgorithmIdentifier {
    pub algorithm: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
    #[defined_by(algorithm)]
    pub parameters: Value,
}

impl<'a> asn1::SimpleAsn1Readable<'a> for AlgorithmIdentifier {
    const TAG: asn1::Tag = <asn1::Sequence as asn1::SimpleAsn1Readable>::TAG;
    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        let oid = asn1::parse(data, |p| {
            let algorithm;
            Ok(Self {
                algorithm: {
                    algorithm = p
                        .read_element()
                        .map_err(|e| e.add_location(asn1::ParseLocation::Field("AlgorithmIdentifier::algorithm")))?;
                    asn1::DefinedByMarker::marker()
                },
                parameters: asn1::read_defined_by(algorithm, p)
                    .map_err(|e| e.add_location(asn1::ParseLocation::Field("AlgorithmIdentifier::parameters")))?,
            })
        });
        // println!("{:?}", oid);
        oid
    }
}

#[derive(asn1::Asn1DefinedByRead, asn1::Asn1DefinedByWrite, PartialEq, Debug, Eq)]
pub enum Value {
    // SM2签名算法, parameters为空,或(NULL)
    #[defined_by(OidSignatureSM2WithSM3)]
    SignatureSM2WithSM3(Option<asn1::Null>),
    // SignatureSM2WithSM3(asn1::<asn1::Null>),
    #[defined_by(OidRSAEncryption)]
    RSAEncryption(Option<asn1::Null>),
    
    #[defined_by(OidSignatureSHA1WithRSA)]
    SignatureSHA1WithRSA(Option<asn1::Null>),
    
    
    // SM2公钥信息
    #[defined_by(OidECPublicKey)]
    ECPublicKey(ECPublicKeyParam),
}


// RFC 3279, here only defined for named curve.
#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
pub enum ECPublicKeyParam{
    NamedCurve(asn1::ObjectIdentifier),
}


#[test]
fn test_algorithm_identifier(){
    let v = AlgorithmIdentifier{
        algorithm: asn1::DefinedByMarker::marker(),
        parameters: Value::SignatureSM2WithSM3(Some(asn1::Null::default())),
    };
    let result = asn1::write_single(&v).unwrap();
    println!("{:x?}", result);
    let vv :AlgorithmIdentifier= asn1::parse_single(&result).unwrap();
    let result = asn1::write_single(&vv).unwrap();
    println!("{:x?}", result);
}

#[test]
fn test_algorithm_identifier_ecpublic_key(){
    let v = AlgorithmIdentifier{
        algorithm: asn1::DefinedByMarker::marker(),
        parameters: Value::ECPublicKey(ECPublicKeyParam::NamedCurve(OidSm2Ecc)),
    };
    let result = asn1::write_single(&v).unwrap();
    println!("{:x?}", result);
    let vv :AlgorithmIdentifier= asn1::parse_single(&result).unwrap();
    let result = asn1::write_single(&vv).unwrap();
    println!("{:x?}", result);
}