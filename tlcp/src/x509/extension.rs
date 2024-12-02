use super::{
    name::*,
    types::*,
};

// some primitive tages.
const TagBoolean: u32 = 0x01;
const TagInteger: u32 = 0x02;
const TagBitString: u32 = 0x03;
const TagOctetString: u32 = 0x04;
const TagNull: u32 = 0x05;
const TagObjectIdentifier: u32 = 0x06;

#[derive(Debug)]
pub struct Extensions<'a> {
    extns: Vec<Extension<'a>>,
}

impl<'a> asn1::Asn1Writable for Extensions<'a> {
    fn write(&self, dest: &mut asn1::Writer<'_>) -> asn1::WriteResult {
        asn1::SequenceOfWriter::new(self.extns.as_slice()).write(dest)
    }
}

impl<'a> asn1::Asn1Readable<'a> for Extensions<'a> {
    fn parse(parser: &mut asn1::Parser<'a>) -> asn1::ParseResult<Self> {
        let mut extns = Vec::new();
        let seqof_extns = parser.read_element::<asn1::SequenceOf<Extension>>()?;
        for extn in seqof_extns {
            extns.push(extn);
        }
        Ok(Extensions { extns: extns })
    }

    fn can_parse(tag: asn1::Tag) -> bool {
        tag == <asn1::SequenceOf<Extension> as asn1::SimpleAsn1Readable>::TAG
    }
}

impl<'a> PartialEq for Extensions<'a> {
    fn eq(&self, other: &Self) -> bool {
        for extn in &self.extns {
            let mut equal = false;
            for other_extn in &other.extns {
                if extn == other_extn {
                    equal = true;
                }
            }
            if !equal {
                return false;
            }
        }
        true
    }
}

impl<'a> Eq for Extensions<'a> {}

// Extensions in GB/T 20518--2018
const OidAuthorityKeyIdentifier: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 35);
const OidSubjectKeyIdentifier: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 14);
const OidKeyUsage: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 15);
const OidExtendedKeyUsage: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 37);
const OidPrivateKeyUsagePeriod: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 16);
const OidCertificatePolicies: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 32);
const OidPolicyMappings: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 33);
const OidSubjectAltName: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 17);
const OidIssuerAltName: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 18);
const OidBasicConstraints: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 19);
const OidNameConstraints: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 30);
const OidPolicyConstraints: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 36);
const OidCRLDistributionPoints: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 31);
const OidInhibitAnyPolicy: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 54);
const OidFreshestCRL: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 46);

// 国内独有
const OidIdentifyCode: asn1::ObjectIdentifier = asn1::oid!(1, 2, 156, 10260, 4, 1, 1);
const OidInsuranceNumber: asn1::ObjectIdentifier = asn1::oid!(1, 2, 156, 10260, 4, 1, 2);
const OidICRegistrationNumber: asn1::ObjectIdentifier = asn1::oid!(1, 2, 156, 10260, 4, 1, 3);
const OidOrganizationCode: asn1::ObjectIdentifier = asn1::oid!(1, 2, 156, 10260, 4, 1, 4);
const OidTaxationNumber: asn1::ObjectIdentifier = asn1::oid!(1, 2, 156, 10260, 4, 1, 5);

// 专有因特网扩展
const OidAuthorityInfoAccess: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 1, 1);
const OidSubjectInformationAccess: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 1, 11);

#[derive(PartialEq, Debug, Eq)]
pub struct Extension<'a> {
    extn_id: asn1::ObjectIdentifier,

    // optional DEFAULT false
    critical: bool,

    // extn_value is wrapped in OCTET STRING.
    extn_value: Value<'a>,
}

impl<'a> asn1::SimpleAsn1Writable for Extension<'a> {
    const TAG: asn1::Tag = <asn1::SequenceWriter as asn1::SimpleAsn1Writable>::TAG;

    fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
        let extn_value = asn1::write_single(&self.extn_value)?;

        let mut w = asn1::Writer::new(dest);
        w.write_element(&self.extn_id)?;

        // DEFAULT false
        w.write_element(&{ asn1::to_optional_default(&self.critical, &(false).into()) })?;

        w.write_element(&extn_value.as_slice())?;
        Ok(())
    }
}

impl<'a> asn1::SimpleAsn1Readable<'a> for Extension<'a> {
    const TAG: asn1::Tag = <asn1::Sequence as asn1::SimpleAsn1Readable>::TAG;
    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        asn1::parse(data, |p| {
            let extn_id = p
                .read_element()
                .map_err(|e| e.add_location(asn1::ParseLocation::Field("ExtensionHelper::extn_id")))?;
            let critical = asn1::from_optional_default(
                p.read_element()
                    .map_err(|e| e.add_location(asn1::ParseLocation::Field("ExtensionHelper::critical")))?,
                false.into(),
            )
            .map_err(|e| e.add_location(asn1::ParseLocation::Field("ExtensionHelper::critical")))?;

            let extn_value = p
                .read_element()
                .map_err(|e| e.add_location(asn1::ParseLocation::Field("ExtensionHelper::extn_value")))?;
            let value = parse_extension_value(&extn_id, extn_value)?;
            Ok(Extension {
                extn_id,
                critical,
                extn_value: value,
            })
        })
    }
}

fn parse_extension_value<'a>(oid: &asn1::ObjectIdentifier, data: &'a [u8]) -> asn1::ParseResult<Value<'a>> {
    match *oid {
        OidAuthorityKeyIdentifier => Ok(Value::AuthorityKeyIdentifier(asn1::parse_single(data)?)),
        OidSubjectKeyIdentifier => Ok(Value::SubjectKeyId(asn1::parse_single(data)?)),
        OidKeyUsage => Ok(Value::KeyUsage(asn1::parse_single(data)?)),
        OidExtendedKeyUsage => Ok(Value::ExtendedKeyUsage(asn1::parse_single(data)?)),
        // OidPrivateKeyUsagePeriod => Ok(Value::PrivateKeyUsagePeriod(asn1::parse_single(data)?)),
        // OidCertificatePolicies => Ok(Value::CertificatePolicies(asn1::parse_single(data)?)),
        // OidPolicyMappings => Ok(Value::PolicyMappings(asn1::parse_single(data)?)),
        OidSubjectAltName => Ok(Value::SubjectAltName(asn1::parse_single(data)?)),
        OidIssuerAltName => Ok(Value::IssuerAltName(asn1::parse_single(data)?)),
        OidBasicConstraints => Ok(Value::BasicConstraints(asn1::parse_single(data)?)),
        // OidNameConstraints => Ok(Value::NameConstraints(asn1::parse_single(data)?)),
        // OidPolicyConstraints => Ok(Value::PolicyConstraints(asn1::parse_single(data)?)),
        OidCRLDistributionPoints => Ok(Value::CRLDistributionPoints(asn1::parse_single(data)?)),
        // OidInhibitAnyPolicy => Ok(Value::InhibitAnyPolicy(asn1::parse_single(data)?)),
        // OidFreshestCRL => Ok(Value::FreshestCRL(asn1::parse_single(data)?)),

        // not recognized extension oid.
        _ => Err(asn1::ParseError::new(asn1::ParseErrorKind::UnknownDefinedBy)
            .add_location(asn1::ParseLocation::Field("ExtensionHelper::extn_value"))),
    }
}

// Value should be wrapped in a OCTET STRING.
#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
enum Value<'a> {
    AuthorityKeyIdentifier(AuthorityKeyIdentifier<'a>),
    SubjectKeyId(SubjectKeyIdentifier<'a>),
    KeyUsage(KeyUsage<'a>),
    ExtendedKeyUsage(ExtendedKeyUsage),
    // PrivateKeyUsagePeriod(PrivateKeyUsagePeriod<'a>),
    // CertificatePolicies(CertificatePolicies<'a>),
    // PolicyMappings(PolicyMappings<'a>),
    SubjectAltName(SubjectAltName<'a>),
    IssuerAltName(IssuerAltName<'a>),
    BasicConstraints(BasicConstraints),
    // NameConstraints(NameConstraints<'a>),
    // PolicyConstraints(PolicyConstraints<'a>),
    CRLDistributionPoints(CRLDistributionPoints<'a>),
    // InhibitAnyPolicy(InhibitAnyPolicy<'a>),
    // FreshestCRL(FreshestCRL<'a>),
}

#[allow(unused_macros)]
macro_rules! DeclareExtensionValue {
    ($type: ident, $critical:expr, $oid: ident) => {
        impl<'a> $type<'a> {
            fn critical() -> bool {
                return $critical;
            }
            fn oid() -> asn1::ObjectIdentifier {
                $oid
            }
        }
    };
}

////////////////////////////////////////////////////////////////
/// AuthorityKeyIdentifier ::= SEQUENCE {
///     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
///     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
///     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
////////////////////////////////////////////////////////////////

type CertificateSerialNumber<'a> = asn1::BigInt<'a>;

#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq, Eq)]
struct AuthorityKeyIdentifier<'a> {
    #[implicit(0)]
    keyidentifier: Option<&'a [u8]>,
    #[implicit(1)]
    authority_cert_issuer: Option<GeneralNames<'a>>,
    #[implicit(2)]
    authorityCertSerialNumber: Option<CertificateSerialNumber<'a>>,
}
impl<'a> AuthorityKeyIdentifier<'a> {
    fn critical() -> bool {
        return false;
    }
    fn oid() -> asn1::ObjectIdentifier {
        OidAuthorityKeyIdentifier
    }
}

////////////////////////////////////////////////////////////////
/// SubjectKeyIdentifier
////////////////////////////////////////////////////////////////

// SubjectKeyIdentifier ::= KeyIdentifier
// KeyIdentifier ::= OCTET STRING
#[derive(PartialEq, Debug, Eq)]
struct SubjectKeyIdentifier<'a> {
    keyidentifier: &'a [u8],
}
impl<'a> SubjectKeyIdentifier<'a> {
    fn critical() -> bool {
        return false;
    }
    fn oid() -> asn1::ObjectIdentifier {
        OidSubjectKeyIdentifier
    }
}

impl<'a> asn1::Asn1Writable for SubjectKeyIdentifier<'a> {
    fn write(&self, dest: &mut asn1::Writer<'_>) -> asn1::WriteResult {
        self.keyidentifier.write(dest)
    }
}

impl<'a> asn1::Asn1Readable<'a> for SubjectKeyIdentifier<'a> {
    fn parse(parser: &mut asn1::Parser<'a>) -> asn1::ParseResult<Self> {
        let keyidentifier: &[u8] = parser.read_element()?;
        Ok(SubjectKeyIdentifier {
            keyidentifier: keyidentifier,
        })
    }

    fn can_parse(tag: asn1::Tag) -> bool {
        tag == asn1::Tag::primitive(TagOctetString)
    }
}

////////////////////////////////////////////////////////////////
/// KeyUsage
////////////////////////////////////////////////////////////////

#[derive(PartialEq, Debug, Eq)]
struct KeyUsage<'a> {
    key_usage: asn1::BitString<'a>,
}
impl<'a> KeyUsage<'a> {
    // 实际上, 可以关键也可以非关键.
    fn critical() -> bool {
        return true;
    }
    fn oid() -> asn1::ObjectIdentifier {
        OidKeyUsage
    }
}

impl<'a> asn1::Asn1Writable for KeyUsage<'a> {
    fn write(&self, dest: &mut asn1::Writer<'_>) -> asn1::WriteResult {
        self.key_usage.write(dest)
    }
}

impl<'a> asn1::Asn1Readable<'a> for KeyUsage<'a> {
    fn parse(parser: &mut asn1::Parser<'a>) -> asn1::ParseResult<Self> {
        let key_usage: asn1::BitString = parser.read_element()?;
        Ok(KeyUsage { key_usage: key_usage })
    }

    fn can_parse(tag: asn1::Tag) -> bool {
        tag == asn1::Tag::primitive(TagBitString)
    }
}

////////////////////////////////////////////////////////////////
/// ExtendedKeyUsage
////////////////////////////////////////////////////////////////

/// ExtendedKeyUsage ::= SEQUENCE OF KeyPurposeId
/// KeyPurposeId ::= OBJECT IDENTIFIER
#[derive(PartialEq, Debug, Eq)]
struct ExtendedKeyUsage {
    key_purpose_ids: Vec<asn1::ObjectIdentifier>,
}

impl ExtendedKeyUsage {
    // 实际上, 可以关键也可以非关键.
    fn critical() -> bool {
        return false;
    }
    fn oid() -> asn1::ObjectIdentifier {
        OidExtendedKeyUsage
    }
}

impl asn1::Asn1Writable for ExtendedKeyUsage {
    fn write(&self, dest: &mut asn1::Writer<'_>) -> asn1::WriteResult {
        asn1::SequenceOfWriter::new(self.key_purpose_ids.as_slice()).write(dest)
    }
}

impl<'a> asn1::Asn1Readable<'a> for ExtendedKeyUsage {
    fn parse(parser: &mut asn1::Parser<'a>) -> asn1::ParseResult<Self> {
        let seqof_key_purpose_ids = parser.read_element::<asn1::SequenceOf<asn1::ObjectIdentifier>>()?;
        Ok(ExtendedKeyUsage {
            key_purpose_ids: seqof_key_purpose_ids.collect(),
        })
    }

    fn can_parse(tag: asn1::Tag) -> bool {
        tag == <asn1::SequenceOf<asn1::ObjectIdentifier> as asn1::SimpleAsn1Readable>::TAG
    }
}

////////////////////////////////////////////////////////////////
/// SubjectAltName
////////////////////////////////////////////////////////////////

/// ExtendedKeyUsage ::= SEQUENCE OF KeyPurposeId
/// KeyPurposeId ::= OBJECT IDENTIFIER
#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
struct SubjectAltName<'a> {
    general_names: GeneralNames<'a>,
}

impl<'a> SubjectAltName<'a> {
    // 实际上, 可以关键也可以非关键.
    fn critical() -> bool {
        return false;
    }
    fn oid() -> asn1::ObjectIdentifier {
        OidSubjectAltName
    }
}

////////////////////////////////////////////////////////////////
/// IssuerAltName
////////////////////////////////////////////////////////////////

/// ExtendedKeyUsage ::= SEQUENCE OF KeyPurposeId
/// KeyPurposeId ::= OBJECT IDENTIFIER
#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
struct IssuerAltName<'a> {
    general_names: GeneralNames<'a>,
}

impl<'a> IssuerAltName<'a> {
    fn critical() -> bool {
        return false;
    }
    fn oid() -> asn1::ObjectIdentifier {
        OidIssuerAltName
    }
}

////////////////////////////////////////////////////////////////
/// BasicConstraints
////////////////////////////////////////////////////////////////

/// ExtendedKeyUsage ::= SEQUENCE OF KeyPurposeId
/// KeyPurposeId ::= OBJECT IDENTIFIER
#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
struct BasicConstraints {
    // #[default(false)]
    ca: bool,

    path_len: Option<i32>,
}

impl BasicConstraints {
    // 实际上, 可以关键也可以非关键.
    fn critical() -> bool {
        return false;
    }
    fn oid() -> asn1::ObjectIdentifier {
        OidBasicConstraints
    }
}

////////////////////////////////////////////////////////////////
/// CRLDistributionPoints
////////////////////////////////////////////////////////////////

// DistributionPointName ::= CHOICE {
//     fullName                [0]     GeneralNames,
//     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
#[derive(PartialEq, Debug, Eq)]
enum DistributionPointName<'a> {
    // #[implicit(0)]
    FullName(GeneralNames<'a>),
    // #[implicit(1)]
    NameRelativeToCRLIssuer(RelativeDistinguishedName<'a>),
}

impl<'a> asn1::SimpleAsn1Readable<'a> for DistributionPointName<'a> {
    const TAG: asn1::Tag = <asn1::Implicit<asn1::Sequence, 0> as asn1::SimpleAsn1Readable>::TAG;

    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        asn1::parse(data, |p| {
            // let tlv: asn1::Tlv<'a> = p.read_element()?;
            // match tlv.tag().value() {
            //     0 => {
            //         Ok(DistributionPointName::FullName(p.read_element::<asn1::Implicit<GeneralNames, 0>>()?.into_inner()))
            //     },
            //     1 => {
            //         Ok(DistributionPointName::NameRelativeToCRLIssuer(p.read_element::<asn1::Implicit<RelativeDistinguishedName, 1>>()?.into_inner()))

            //     },
            //     _ => {
            //         Err(asn1::ParseError::new(asn1::ParseErrorKind::InvalidTag))
            //     }
            // }
            let v = p.read_element::<asn1::Implicit<GeneralNames, 0>>();
            // println!("{:?}",v);
            if let Ok(v) = v {
                return Ok(DistributionPointName::FullName(v.into_inner()));
            }
            if let Ok(v) = p.read_element::<asn1::Implicit<RelativeDistinguishedName, 1>>() {
                return Ok(DistributionPointName::NameRelativeToCRLIssuer(v.into_inner()));
            }
            return Err(asn1::ParseError::new(asn1::ParseErrorKind::InvalidTag));
        })
    }
}

impl<'a> asn1::SimpleAsn1Writable for DistributionPointName<'a> {
    const TAG: asn1::Tag = <asn1::Implicit<asn1::Sequence, 0> as asn1::SimpleAsn1Writable>::TAG;

    fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
        let mut w = asn1::Writer::new(dest);
        match self {
            DistributionPointName::FullName(general_names) => {
                // w.write_implicit_element(general_names, 0)?;
                w.write_element(&asn1::Implicit::<_, 0>::new(&general_names))?;
            }
            DistributionPointName::NameRelativeToCRLIssuer(relative_distinguished_name) => {
                // w.write_implicit_element(relative_distinguished_name, 1)?;
                w.write_element(&asn1::Implicit::<_, 1>::new(&relative_distinguished_name))?;

            }
        }
        // if let Some(distribution_point) = self.distribution_point{
        //     w.write_optional_implicit_element(&self.distribution_point,0)?;
        // }
        // w.write_optional_implicit_element(&self.reasons,1)?;
        // w.write_optional_implicit_element(&self.crl_issuer,2)?;

        Ok(())
    }
}

// DistributionPoint ::= SEQUENCE {
//     distributionPoint       [0]     DistributionPointName OPTIONAL,
//     reasons                 [1]     ReasonFlags OPTIONAL,
//     cRLIssuer               [2]     GeneralNames OPTIONAL }
#[derive(asn1::Asn1Write, PartialEq, Debug, Eq)]
pub struct DistributionPoint<'a> {
    #[implicit(0)]
    distribution_point: Option<DistributionPointName<'a>>,
    #[implicit(1)]
    reasons: Option<asn1::BitString<'a>>,
    #[implicit(2)]
    crl_issuer: Option<GeneralNames<'a>>,
}

impl<'a> asn1::SimpleAsn1Readable<'a> for DistributionPoint<'a> {
    const TAG: asn1::Tag = <asn1::Sequence as asn1::SimpleAsn1Readable>::TAG;
    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        asn1::parse(data, |p| {
            Ok(Self {
                distribution_point: p
                    .read_element::<Option<asn1::Implicit<_, 0>>>()
                    .map_err(|e| e.add_location(asn1::ParseLocation::Field("DistributionPoint::distribution_point")))?
                    .map(asn1::Implicit::into_inner),
                reasons: p
                    .read_element::<Option<asn1::Implicit<_, 1>>>()
                    .map_err(|e| e.add_location(asn1::ParseLocation::Field("DistributionPoint::reasons")))?
                    .map(asn1::Implicit::into_inner),
                crl_issuer: p
                    .read_element::<Option<asn1::Implicit<_, 2>>>()
                    .map_err(|e| e.add_location(asn1::ParseLocation::Field("DistributionPoint::crl_issuer")))?
                    .map(asn1::Implicit::into_inner),
            })
        })
    }
}

// impl<'a> asn1::SimpleAsn1Readable<'a> for DistributionPoint<'a> {
//     const TAG: asn1::Tag = <asn1::Sequence as asn1::SimpleAsn1Readable>::TAG;

//     fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
//         asn1::parse(data, |p| {
//             let mut distribution_point = None;
//             let mut reasons= None;
//             let mut crl_issuer = None;
//             while !p.is_empty(){
//                 let tlv: asn1::Tlv<'a> = p.read_element()?;
//                 match tlv.tag().value() {
//                     0 => {
//                         distribution_point = Some(p.read_element::<DistributionPointName>()?);
//                     },
//                     1 => {
//                         reasons = Some(p.read_element::<asn1::BitString>()?);
//                     },
//                     2 => {
//                         crl_issuer = Some(p.read_element::<GeneralNames>()?);
//                     },
//                     _ => {
//                         return Err(asn1::ParseError::new(asn1::ParseErrorKind::InvalidTag));
//                     }
//                 }
//             }

//             Ok(DistributionPoint {
//                 distribution_point,
//                 reasons,
//                 crl_issuer,
//             })
//         })
//     }
// }

// impl<'a> asn1::SimpleAsn1Writable for DistributionPoint<'a> {
//     const TAG: asn1::Tag = <asn1::Sequence as asn1::SimpleAsn1Writable>::TAG;

//     fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
//         let mut w = asn1::Writer::new(dest);
//         if let Some(distribution_point) = self.distribution_point{
//             w.write_optional_implicit_element(&self.distribution_point,0)?;
//         }
//         w.write_optional_implicit_element(&self.reasons,1)?;
//         w.write_optional_implicit_element(&self.crl_issuer,2)?;

//         Ok(())

//     }
// }

// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
#[derive(PartialEq, Debug, Eq)]
struct CRLDistributionPoints<'a> {
    distribution_points: Vec<DistributionPoint<'a>>,
}

impl<'a> CRLDistributionPoints<'a> {
    // 实际上, 可以关键也可以非关键.
    fn critical() -> bool {
        return false;
    }
    fn oid() -> asn1::ObjectIdentifier {
        OidCRLDistributionPoints
    }
}

impl<'a> asn1::SimpleAsn1Readable<'a> for CRLDistributionPoints<'a> {
    const TAG: asn1::Tag = <asn1::SequenceOf<DistributionPoint> as asn1::SimpleAsn1Readable>::TAG;

    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        asn1::parse(data, |p| {
            let mut distribution_points = Vec::new();
            while !p.is_empty() {
                // read one RelativeDistinguishedName
                distribution_points.push(p.read_element::<DistributionPoint>()?);
            }
            Ok(CRLDistributionPoints { distribution_points })
        })
    }
}

impl<'a> asn1::SimpleAsn1Writable for CRLDistributionPoints<'a> {
    const TAG: asn1::Tag = <asn1::SequenceOf<DistributionPoint> as asn1::SimpleAsn1Writable>::TAG;

    fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
        let mut distribution_points = Vec::new();
        for point in &self.distribution_points {
            distribution_points.push(point);
        }
        asn1::SequenceOfWriter::new(distribution_points).write_data(dest)
    }
}

#[cfg(test)]
mod tests {
    use crate::x509::{name::{self, AttributeTypeAndValue, StringChoice}, print_string::PrintableString};

    use super::*;

    #[test]
    fn test_extension() {
        let keyidentifier = [1; 20];

        let ext1 = Extension {
            extn_id: OidAuthorityKeyIdentifier,
            critical: AuthorityKeyIdentifier::critical(),
            extn_value: Value::AuthorityKeyIdentifier(AuthorityKeyIdentifier {
                keyidentifier: Some(&keyidentifier),
                authority_cert_issuer: None,
                authorityCertSerialNumber: None,
            }),
        };
        let result1 = asn1::write_single(&ext1).unwrap();
        println!("{:02x?}", result1);

        let ext2 = asn1::parse_single::<Extension>(&result1).unwrap();
        println!("{:?}", ext2);

        assert_eq!(ext1, ext2);
        let result2 = asn1::write_single(&ext2).unwrap();

        assert!(do_vecs_match(&result1, &result2));
    }

    fn do_vecs_match<T: PartialEq>(a: &Vec<T>, b: &Vec<T>) -> bool {
        let matching = a.iter().zip(b.iter()).filter(|&(a, b)| a == b).count();
        matching == a.len() && matching == b.len()
    }

    #[test]
    fn test_extensions() {
        let keyidentifier1 = [1; 20];

        let keyidentifier2 = [2; 20];
        let KeyUsage = [0xC0];

        let v1 = Extensions {
            extns: vec![
                Extension {
                    extn_id: OidAuthorityKeyIdentifier,
                    critical: AuthorityKeyIdentifier::critical(),
                    extn_value: Value::AuthorityKeyIdentifier(AuthorityKeyIdentifier {
                        keyidentifier: Some(&keyidentifier1),
                        authority_cert_issuer: None,
                        authorityCertSerialNumber: None,
                    }),
                },
                Extension {
                    extn_id: OidSubjectKeyIdentifier,
                    critical: AuthorityKeyIdentifier::critical(),
                    extn_value: Value::SubjectKeyId(SubjectKeyIdentifier {
                        keyidentifier: &keyidentifier2,
                    }),
                },
                Extension {
                    extn_id: OidKeyUsage,
                    critical: true,
                    extn_value: Value::KeyUsage(KeyUsage {
                        key_usage: asn1::BitString::new(&KeyUsage, 0).unwrap(),
                    }),
                },
                Extension {
                    extn_id: OidExtendedKeyUsage,
                    critical: false,
                    extn_value: Value::ExtendedKeyUsage(ExtendedKeyUsage {
                        key_purpose_ids: vec![OidIdentifyCode, OidIssuerAltName],
                    }),
                },
                Extension {
                    extn_id: OidBasicConstraints,
                    critical: false,
                    extn_value: Value::BasicConstraints(BasicConstraints {
                        ca: false,
                        path_len: None,
                    }),
                },
            ],
        };

        let result1 = asn1::write_single(&v1).unwrap();
        println!("{:02x?}", result1);

        let v2 = asn1::parse_single::<Extensions>(&result1).unwrap();
        assert_eq!(v1, v2);
        let result2 = asn1::write_single(&v2).unwrap();

        assert!(do_vecs_match(&result1, &result2));
    }

    #[test]
    fn test_distribution_names() {
        // 30 0b
        //    82 03 646e73
        //    87 04 01020304
        let general_name = GeneralName::DirectoryName(Name {
            rdn: vec![RelativeDistinguishedName {
                atv: vec![AttributeTypeAndValue {
                    typ: asn1::DefinedByMarker::marker(),
                    value: name::Value::Country(StringChoice::PrintableString(
                        PrintableString::new("CN").unwrap(),
                    )),
                }],
            }],
        });
        // println!("{:02x?}", asn1::write_single(&general_name).unwrap());
        let general_names = GeneralNames { v: vec![general_name] };
        // println!("{:02x?}", asn1::write_single(&general_names).unwrap());

        let dis_names = DistributionPointName::FullName(general_names);
        let b = asn1::write_single(&dis_names).unwrap();
        println!("{:02x?}", b);
        let dis_names = asn1::parse_single::<DistributionPointName>(&b).unwrap();

        let v = asn1::Implicit::<_, 0>::new(dis_names);
        println!("{:02x?}", asn1::write_single(&v).unwrap());
    }

    #[test]
    fn test_distribution_point() {
        // 30 0b
        //    82 03 646e73
        //    87 04 01020304
        let general_name = GeneralName::DirectoryName(Name {
            rdn: vec![RelativeDistinguishedName {
                atv: vec![AttributeTypeAndValue {
                    typ: asn1::DefinedByMarker::marker(),
                    value: name::Value::Country(StringChoice::PrintableString(
                        PrintableString::new("CN").unwrap(),
                    )),
                }],
            }],
        });
        // println!("{:02x?}", asn1::write_single(&general_name).unwrap());
        let general_names = GeneralNames { v: vec![general_name] };
        // println!("{:02x?}", asn1::write_single(&general_names).unwrap());

        let dis_names = DistributionPointName::FullName(general_names);
        let b = asn1::write_single(&dis_names).unwrap();
        // println!("{:02x?}", b);
        let dis_names = asn1::parse_single::<DistributionPointName>(&b).unwrap();

        let dis_point = DistributionPoint {
            distribution_point: Some(dis_names),
            reasons: None,
            crl_issuer: None,
        };
        let b = asn1::write_single(&dis_point).unwrap();
        println!("{:02x?}", b);
        let dis_point = asn1::parse_single::<DistributionPoint>(&b).unwrap();
        let b = asn1::write_single(&dis_point).unwrap();
        println!("{:02x?}", b);
        
        // let v = asn1::Implicit::<_, 0>::new(dis_point);
        // println!("{:02x?}", asn1::write_single(&v).unwrap());
    }


    #[test]
    fn test_distribution_point2() {
        // 30 0b
        //    82 03 646e73
        //    87 04 01020304
        let general_name = GeneralName::UniformResourceIdentifier(
            asn1::IA5String::new("abc").unwrap()
        );
        // println!("{:02x?}", asn1::write_single(&general_name).unwrap());
        let general_names = GeneralNames { v: vec![general_name] };
        // println!("{:02x?}", asn1::write_single(&general_names).unwrap());

        let dis_names = DistributionPointName::FullName(general_names);
        let b = asn1::write_single(&dis_names).unwrap();
        println!("{:02x?}", b);
        let dis_names = asn1::parse_single::<DistributionPointName>(&b).unwrap();

        let dis_point = DistributionPoint {
            distribution_point: Some(dis_names),
            reasons: None,
            crl_issuer: None,
        };
        let b = asn1::write_single(&dis_point).unwrap();
        println!("{:02x?}", b);
        let dis_point = asn1::parse_single::<DistributionPoint>(&b).unwrap();
        let b = asn1::write_single(&dis_point).unwrap();
        println!("{:02x?}", b);
        
        // let v = asn1::Implicit::<_, 0>::new(dis_point);
        // println!("{:02x?}", asn1::write_single(&v).unwrap());
    }

    
}
