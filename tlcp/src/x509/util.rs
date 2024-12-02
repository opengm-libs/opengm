// // Type Any is a just a TLV structure, for un-parsed types.
// #[derive(PartialEq, Debug, Eq)]
// pub struct Asn1Any<'a> {
//     pub tlv: asn1::Tlv<'a>
// }

 
// impl<'a> asn1::SimpleAsn1Readable<'a> for Asn1Any<'a> {
//     const TAG: asn1::Tag = <asn1::Sequence as asn1::SimpleAsn1Readable>::TAG;

//     fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
//         asn1::parse(data, |p| {
//             let tlv: asn1::Tlv = p.read_element()
//             .map_err(|e| e.add_location(asn1::ParseLocation::Field("Any")))?;
//             Ok(Asn1Any{tlv})
//         })
//     }
// }

// impl<'a> asn1::SimpleAsn1Writable for Asn1Any<'a> {
    
//     const TAG: asn1::Tag = <asn1::SequenceWriter as asn1::SimpleAsn1Writable>::TAG;
//     fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
//         let mut w = asn1::Writer::new(dest);
//         w.write_element(&self.tlv)

//         // self.tlv.(&mut w)?;
//         // w.write_tlv(self.tlv.tag(), |dest| {
//         //     dest.push_slice(self.tlv.data())
//         // })
//     }
// }



// #[derive(asn1::Asn1Read, asn1::Asn1Write)]
// struct TypeSeqOf<'a>{
//     a: Vec::<i32>,
// }

// #[test]
// fn test_seqof(){
//     let seq = TypeSeqOf{
//         a: asn1::SequenceOf:
//     }

// }