use std::{fmt::Debug, iter::zip};

use super::print_string::PrintableString;

pub const OidCommonName: asn1::ObjectIdentifier = asn1::oid!(2, 5, 4, 3);
pub const OidSerialNumber: asn1::ObjectIdentifier = asn1::oid!(2, 5, 4, 5);
pub const OidCountry: asn1::ObjectIdentifier = asn1::oid!(2, 5, 4, 6);
pub const OidLocality: asn1::ObjectIdentifier = asn1::oid!(2, 5, 4, 7);
pub const OidProvince: asn1::ObjectIdentifier = asn1::oid!(2, 5, 4, 8);
pub const OidStreetAddress: asn1::ObjectIdentifier = asn1::oid!(2, 5, 4, 9);
pub const OidOrganization: asn1::ObjectIdentifier = asn1::oid!(2, 5, 4, 10);
pub const OidOrganizationalUnit: asn1::ObjectIdentifier = asn1::oid!(2, 5, 4, 11);
pub const OidPostalCode: asn1::ObjectIdentifier = asn1::oid!(2, 5, 4, 17);

//   - Country
//   - Organization
//   - OrganizationalUnit
//   - Locality
//   - Province
//   - StreetAddress
//   - PostalCode
//
#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq, Eq)]
pub struct AttributeTypeAndValue<'a> {
    pub typ: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
    #[defined_by(typ)]
    pub value: Value<'a>,
}

#[derive(asn1::Asn1DefinedByRead, asn1::Asn1DefinedByWrite, PartialEq, Debug, Eq)]
pub enum Value<'a> {
    #[defined_by(OidCountry)]
    Country(StringChoice<'a>),
    #[defined_by(OidOrganization)]
    Organization(StringChoice<'a>),
    #[defined_by(OidOrganizationalUnit)]
    OrganizationalUnit(StringChoice<'a>),
    #[defined_by(OidCommonName)]
    CommonName(StringChoice<'a>),
    #[defined_by(OidLocality)]
    Locality(StringChoice<'a>),
    #[defined_by(OidProvince)]
    Province(StringChoice<'a>),
    #[defined_by(OidStreetAddress)]
    StreetAddress(StringChoice<'a>),
    #[defined_by(OidPostalCode)]
    PostalCode(StringChoice<'a>),
    #[defined_by(OidSerialNumber)]
    SerialNumber(StringChoice<'a>),
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
pub enum StringChoice<'a> {
    IA5String(asn1::IA5String<'a>),
    Utf8String(asn1::Utf8String<'a>),
    BMPString(asn1::BMPString<'a>),
    UniversalString(asn1::UniversalString<'a>),
    PrintableString(PrintableString<'a>),
}


#[derive(Debug)]
pub struct Name<'a> {
    // SEQUENCE OF RelativeDistinguishedName
    pub rdn: Vec<RelativeDistinguishedName<'a>>,
}

#[derive(Debug,PartialEq,Eq)]
pub struct RelativeDistinguishedName<'a> {
    // SET OF AttributeTypeAndValue
    pub atv: Vec<AttributeTypeAndValue<'a>>,
}

impl<'a> asn1::SimpleAsn1Readable<'a> for RelativeDistinguishedName<'a> {
    const TAG: asn1::Tag = <asn1::SetOf<AttributeTypeAndValue> as asn1::SimpleAsn1Readable>::TAG;

    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        asn1::parse(data, |p| {
            let mut atv = Vec::new();
            while !p.is_empty() {
                // read one RelativeDistinguishedName
                let v = p.read_element::<AttributeTypeAndValue>();
                if v.is_ok(){
                    atv.push(v.unwrap());
                }
            }
            Ok(RelativeDistinguishedName { atv })
        })
    }
}

impl<'a> asn1::SimpleAsn1Writable for RelativeDistinguishedName<'a> {
    const TAG: asn1::Tag = <asn1::SetOf<AttributeTypeAndValue> as asn1::SimpleAsn1Writable>::TAG;

    fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
        let mut setof_atv = Vec::new();
        for atv in &self.atv {
            setof_atv.push(atv);
        }
        asn1::SetOfWriter::new(setof_atv).write_data(dest)
    }
}


impl<'a> RelativeDistinguishedName<'a> {
    fn has_atv(&self, atv: &AttributeTypeAndValue) -> bool {
        for self_atv in &self.atv {
            if self_atv == atv {
                return true;
            }
        }
        false
    }
}

impl<'a> asn1::SimpleAsn1Readable<'a> for Name<'a> {
    const TAG: asn1::Tag = <asn1::SequenceOf<RelativeDistinguishedName> as asn1::SimpleAsn1Readable>::TAG;

    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        asn1::parse(data, |p| {
            let mut rdn = Vec::new();
            while !p.is_empty() {
                // read one RelativeDistinguishedName
                rdn.push(p.read_element::<RelativeDistinguishedName>()?);
            }
            Ok(Name { rdn })
            // Ok(
            //     Name { 
            //         rdn: p.read_element::<asn1::SequenceOf<RelativeDistinguishedName>>()?
            //         .collect()
            // })
        })
    }
}

impl<'a> asn1::SimpleAsn1Writable for Name<'a> {
    const TAG: asn1::Tag = <asn1::SequenceOf<RelativeDistinguishedName> as asn1::SimpleAsn1Writable>::TAG;

    // Each atv is wrapped in SEQUENCE OF{ SET OF { ATV } }, to void sort the SET.
    // EXAMPLE:
    // 30 20                        -- RDNSequence := SEQUENCE OF RelativeDistinguishedName
    //    31 11                     -- SET OF AttributeTypeAndValue
    //       30 0f                  -- AttributeTypeAndValue
    //          06 03 550403
    //          13 08 7a68616e6773616e
    //    31 0b                     -- SET OF AttributeTypeAndValue
    //       30 09                  -- AttributeTypeAndValue
    //          06 03 550406
    //          13 02 434e
    fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
        let mut seqof_rdn = Vec::new();
        for rdn in &self.rdn {
            seqof_rdn.push(rdn);
        }
        asn1::SequenceOfWriter::new(seqof_rdn).write_data(dest)
    }
}


impl<'a> PartialEq for Name<'a> {
    fn eq(&self, other: &Self) -> bool {
        for (rdn, other_rdn) in zip(&self.rdn, &other.rdn) {
            for atv in &rdn.atv {
                if !other_rdn.has_atv(atv) {
                    return false;
                }
            }
        }
        true
    }
}

impl<'a> Eq for Name<'a> {}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

    #[test]
    fn test_attribute_type_and_value() {
        let v = AttributeTypeAndValue {
            typ: asn1::DefinedByMarker::marker(),
            value: Value::Country(StringChoice::PrintableString(
                PrintableString::new("abc").unwrap(),
            )),
        };
        let result = asn1::write_single(&v).unwrap();
        println!("{:02x?}", result);
    }

    fn do_vecs_match<T: PartialEq>(a: &Vec<T>, b: &Vec<T>) -> bool {
        let matching = a.iter().zip(b.iter()).filter(|&(a, b)| a == b).count();
        matching == a.len() && matching == b.len()
    }

    #[test]
    fn test_rdnsequence() {
        let v1 = Name {
            rdn: vec![
                RelativeDistinguishedName {
                    atv: vec![AttributeTypeAndValue {
                        typ: asn1::DefinedByMarker::marker(),
                        value: Value::CommonName(StringChoice::PrintableString(
                            PrintableString::new("zhangsan").unwrap(),
                        )),
                    }],
                },
                RelativeDistinguishedName {
                    atv: vec![AttributeTypeAndValue {
                        typ: asn1::DefinedByMarker::marker(),
                        value: Value::Country(StringChoice::PrintableString(PrintableString::new("CN").unwrap())),
                    }],
                },
            ],
        };

        let result1 = asn1::write_single(&v1).unwrap();
        println!("{:02x?}", result1);

        let v2 = asn1::parse_single::<Name>(&result1).unwrap();
        assert_eq!(v1, v2);
        let result2 = asn1::write_single(&v2).unwrap();

        assert!(do_vecs_match(&result1, &result2));
    }
}
