use asn1::Asn1Writable;

use super::{name::Name, print_string::PrintableString};

// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
#[derive(PartialEq, Debug, Eq)]
pub struct GeneralNames<'a> {
    pub v: Vec<GeneralName<'a>>,
}

impl<'a> asn1::SimpleAsn1Readable<'a> for GeneralNames<'a> {
    const TAG: asn1::Tag = <asn1::SequenceOf<GeneralName<'a>> as asn1::SimpleAsn1Readable>::TAG;
    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        asn1::parse(data, |p| {
            let mut v = Vec::new();
            while !p.is_empty(){
                v.push(p.read_element::<GeneralName<'a>>()?)
            }
            Ok(GeneralNames {
                v
            })
        })
    }
}

impl<'a> asn1::SimpleAsn1Writable for GeneralNames<'a> {
    const TAG: asn1::Tag = <asn1::SequenceOf<GeneralName<'a>> as asn1::SimpleAsn1Writable>::TAG;
    fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
        let mut seqof = Vec::new();
        let mut w = asn1::Writer::new(dest);
        for item in &self.v {
            seqof.push(item);
            item.write(&mut w)?;
        }
        Ok(())
    }
}

// GeneralName ::= CHOICE {
//     otherName                 [0]  AnotherName,
//     rfc822Name                [1]  IA5String,
//     dNSName                   [2]  IA5String,
//     x400Address               [3]  ORAddress,
//     directoryName             [4]  Name,
//     ediPartyName              [5]  EDIPartyName,
//     uniformResourceIdentifier [6]  IA5String,
//     iPAddress                 [7]  OCTET STRING,
//     registeredID              [8]  OBJECT IDENTIFIER }
#[derive(asn1::Asn1Write, PartialEq, Debug, Eq)]
pub enum GeneralName<'a> {
    #[explicit(0)]
    OtherName(OtherName<'a>),
    #[implicit(1)]
    Rfc822Name(asn1::IA5String<'a>),
    #[implicit(2)]
    DNSName(asn1::IA5String<'a>),
    #[explicit(3)]
    X400Address(ORAddress<'a>),
    #[explicit(4)]
    DirectoryName(Name<'a>),
    #[explicit(5)]
    EdiPartyName(EDIPartyName<'a>),
    #[implicit(6)]
    UniformResourceIdentifier(asn1::IA5String<'a>),
    #[implicit(7)]
    IPAddress(&'a [u8]),
    #[implicit(8)]
    RegisteredID(asn1::ObjectIdentifier),
}

// Recursive expansion of asn1::Asn1Read macro
// ============================================

impl<'a> asn1::Asn1Readable<'a> for GeneralName<'a> {
    fn parse(parser: &mut asn1::Parser<'a>) -> asn1::ParseResult<Self> {
        let tlv = parser.read_element::<asn1::Tlv>()?;
        if tlv.tag() == asn1::explicit_tag(0) {
            return Ok(GeneralName::OtherName(asn1::parse(tlv.full_data(), |p| {
                Ok(p.read_element::<asn1::Explicit<_, 0>>()
                    .map_err(|e| e.add_location(asn1::ParseLocation::Field("GeneralName::OtherName")))?
                    .into_inner())
            })?));
        }
        if tlv.tag() == asn1::implicit_tag(1, <asn1::IA5String<'a> as asn1::SimpleAsn1Readable>::TAG) {
            return Ok(GeneralName::Rfc822Name(asn1::parse(tlv.full_data(), |p| {
                Ok(p.read_element::<asn1::Implicit<_, 1>>()
                    .map_err(|e| e.add_location(asn1::ParseLocation::Field("GeneralName::Rfc822Name")))?
                    .into_inner())
            })?));
        }
        if tlv.tag() == asn1::implicit_tag(2, <asn1::IA5String<'a> as asn1::SimpleAsn1Readable>::TAG) {
            return Ok(GeneralName::DNSName(asn1::parse(tlv.full_data(), |p| {
                Ok(p.read_element::<asn1::Implicit<_, 2>>()
                    .map_err(|e| e.add_location(asn1::ParseLocation::Field("GeneralName::DNSName")))?
                    .into_inner())
            })?));
        }
        if tlv.tag() == asn1::explicit_tag(3) {
            return Ok(GeneralName::X400Address(asn1::parse(tlv.full_data(), |p| {
                Ok(p.read_element::<asn1::Explicit<_, 3>>()
                    .map_err(|e| e.add_location(asn1::ParseLocation::Field("GeneralName::X400Address")))?
                    .into_inner())
            })?));
        }
        if tlv.tag() == asn1::explicit_tag(4) {
            return Ok(GeneralName::DirectoryName(asn1::parse(tlv.full_data(), |p| {
                Ok(p.read_element::<asn1::Explicit<_, 4>>()
                    .map_err(|e| e.add_location(asn1::ParseLocation::Field("GeneralName::DirectoryName")))?
                    .into_inner())
            })?));
        }
        if tlv.tag() == asn1::explicit_tag(5) {
            return Ok(GeneralName::EdiPartyName(asn1::parse(tlv.full_data(), |p| {
                Ok(p.read_element::<asn1::Explicit<_, 5>>()
                    .map_err(|e| e.add_location(asn1::ParseLocation::Field("GeneralName::EdiPartyName")))?
                    .into_inner())
            })?));
        }
        if tlv.tag() == asn1::implicit_tag(6, <asn1::IA5String<'a> as asn1::SimpleAsn1Readable>::TAG) {
            return Ok(GeneralName::UniformResourceIdentifier(asn1::parse(
                tlv.full_data(),
                |p| {
                    Ok(p.read_element::<asn1::Implicit<_, 6>>()
                        .map_err(|e| {
                            e.add_location(asn1::ParseLocation::Field("GeneralName::UniformResourceIdentifier"))
                        })?
                        .into_inner())
                },
            )?));
        }
        if tlv.tag() == asn1::implicit_tag(7, <&'a [u8] as asn1::SimpleAsn1Readable>::TAG) {
            return Ok(GeneralName::IPAddress(asn1::parse(tlv.full_data(), |p| {
                Ok(p.read_element::<asn1::Implicit<_, 7>>()
                    .map_err(|e| e.add_location(asn1::ParseLocation::Field("GeneralName::IPAddress")))?
                    .into_inner())
            })?));
        }
        if tlv.tag() == asn1::implicit_tag(8, <asn1::ObjectIdentifier as asn1::SimpleAsn1Readable>::TAG) {
            return Ok(GeneralName::RegisteredID(asn1::parse(tlv.full_data(), |p| {
                Ok(p.read_element::<asn1::Implicit<_, 8>>()
                    .map_err(|e| e.add_location(asn1::ParseLocation::Field("GeneralName::RegisteredID")))?
                    .into_inner())
            })?));
        }
        Err(asn1::ParseError::new(asn1::ParseErrorKind::UnexpectedTag {
            actual: tlv.tag(),
        }))
    }
    fn can_parse(tag: asn1::Tag) -> bool {
        if tag == asn1::explicit_tag(0) {
            return true;
        }
        if tag == asn1::implicit_tag(1, <asn1::IA5String<'a> as asn1::SimpleAsn1Readable>::TAG) {
            return true;
        }
        if tag == asn1::implicit_tag(2, <asn1::IA5String<'a> as asn1::SimpleAsn1Readable>::TAG) {
            return true;
        }
        if tag == asn1::explicit_tag(3) {
            return true;
        }
        if tag == asn1::explicit_tag(4) {
            return true;
        }
        if tag == asn1::explicit_tag(5) {
            return true;
        }
        if tag == asn1::implicit_tag(6, <asn1::IA5String<'a> as asn1::SimpleAsn1Readable>::TAG) {
            return true;
        }
        if tag == asn1::implicit_tag(7, <&'a [u8] as asn1::SimpleAsn1Readable>::TAG) {
            return true;
        }
        if tag == asn1::implicit_tag(8, <asn1::ObjectIdentifier as asn1::SimpleAsn1Readable>::TAG) {
            return true;
        }
        false
    }
}

// OtherName ::= SEQUENCE {
//     type-id    OBJECT IDENTIFIER,
//     value      [0] EXPLICIT ANY DEFINED BY type-id }
#[derive(PartialEq, Debug, Eq)]
pub struct OtherName<'a> {
    type_id: asn1::ObjectIdentifier,
    // #[explicit(0)]
    value: asn1::Tlv<'a>,
}

impl<'a> asn1::SimpleAsn1Readable<'a> for OtherName<'a> {
    const TAG: asn1::Tag = <asn1::Sequence as asn1::SimpleAsn1Readable>::TAG;
    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        asn1::parse(data, |p| {
            let type_id = p
                .read_element()
                .map_err(|e| e.add_location(asn1::ParseLocation::Field("AnotherName::type_id")))?;
            let value = p
                .read_element::<asn1::Explicit<_, 0>>()
                .map_err(|e| e.add_location(asn1::ParseLocation::Field("AnotherName::value")))?
                .into_inner();
            Ok(Self { type_id, value })
        })
    }
}

impl<'a> asn1::SimpleAsn1Writable for OtherName<'a> {
    const TAG: asn1::Tag = <asn1::SequenceWriter as asn1::SimpleAsn1Writable>::TAG;
    fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
        let mut w = asn1::Writer::new(dest);
        w.write_element(&self.type_id)?;
        // w.write_explicit_element(&self.value, 0)?;
        w.write_element(&asn1::Explicit::<_, 0>::new(&self.value))?;
        Ok(())
    }
}

//
// ORAddress ::= SEQUENCE {
//     built-in-standard-attributes BuiltInStandardAttributes,
//     built-in-domain-defined-attributes
//                     BuiltInDomainDefinedAttributes OPTIONAL,
//     -- see also teletex-domain-defined-attributes
//     extension-attributes ExtensionAttributes OPTIONAL }
// BuiltInStandardAttributes ::= ...
//
// FIXME: just parse and store in a tlv
#[derive(PartialEq, Debug, Eq)]
pub struct ORAddress<'a> {
    tlv: asn1::Tlv<'a>,
}

impl<'a> asn1::SimpleAsn1Readable<'a> for ORAddress<'a> {
    const TAG: asn1::Tag = <asn1::Sequence as asn1::SimpleAsn1Readable>::TAG;

    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        asn1::parse(data, |p| {
            let tlv: asn1::Tlv = p
                .read_element()
                .map_err(|e| e.add_location(asn1::ParseLocation::Field("ORAddress")))?;
            Ok(ORAddress { tlv })
        })
    }
}

impl<'a> asn1::SimpleAsn1Writable for ORAddress<'a> {
    const TAG: asn1::Tag = <asn1::Sequence as asn1::SimpleAsn1Writable>::TAG;

    fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
        let mut w = asn1::Writer::new(dest);
        w.write_element(&self.tlv)
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
pub struct EDIPartyName<'a> {
    name_assigner: DirectoryString<'a>,
    party_name: DirectoryString<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
pub enum DirectoryString<'a> {
    // teletexString    (asn1::<'a>),
    PrintableString(PrintableString<'a>),
    UniversalString(asn1::UniversalString<'a>),
    UTF8String(asn1::Utf8String<'a>),
    BMPString(asn1::BMPString<'a>),
}

#[cfg(test)]
mod tests {
    use crate::x509::{name::{self, AttributeTypeAndValue, OidCommonName, RelativeDistinguishedName, StringChoice}, print_string::PrintableString};

    use super::*;

    // 30 0e
    //    06 03 550403
    //    a0 07
    //       13 05 68656c6c6f
    #[test]
    fn test_anothername() {
        let v1 = PrintableString::new("hello").unwrap();
        let v2 = asn1::write_single(&v1).unwrap();
        let tlv: asn1::Tlv = asn1::parse_single(v2.as_slice()).unwrap();

        let an = OtherName {
            type_id: OidCommonName,
            value: tlv,
        };
        println!("{:02x?}", asn1::write_single(&an).unwrap());
    }

    #[test]
    fn test_generalname_ORAddress() {
        let v1 = PrintableString::new("hello").unwrap();
        let v2 = asn1::write_single(&v1).unwrap();
        let tlv: asn1::Tlv = asn1::parse_single(v2.as_slice()).unwrap();

        let an = GeneralName::X400Address(ORAddress { tlv });
        println!("{:02x?}", asn1::write_single(&an).unwrap());
    }

    #[test]
    fn test_generalnames() {
        // 30 0b
        //    82 03 646e73
        //    87 04 01020304
        let general_name = GeneralName::DirectoryName(
            Name{
                rdn: vec![RelativeDistinguishedName{ 
                    atv: vec![
                        AttributeTypeAndValue {
                            typ: asn1::DefinedByMarker::marker(),
                            value: name::Value::Country(StringChoice::PrintableString(PrintableString::new("CN").unwrap())),
                        },
                    ]
                }],
            }
        );
        println!("{:02x?}", asn1::write_single(&general_name).unwrap());
        let general_names = GeneralNames{v: vec![general_name]};
        println!("{:02x?}", asn1::write_single(&general_names).unwrap());
        let v = asn1::Implicit::<_, 0>::new(general_names);
        println!("{:02x?}", asn1::write_single(&v).unwrap());
    }


    #[test]
    fn test_generalnames2() {
        // 30 0b
        //    82 03 646e73
        //    87 04 01020304
        let general_name = GeneralName::UniformResourceIdentifier(
            asn1::IA5String::new("abc").unwrap()
        );
        println!("{:02x?}", asn1::write_single(&general_name).unwrap());
        let general_names = GeneralNames{v: vec![general_name]};
        println!("{:02x?}", asn1::write_single(&general_names).unwrap());
        let v = asn1::Implicit::<_, 0>::new(general_names);
        println!("{:02x?}", asn1::write_single(&v).unwrap());
    }
}
