
/// Type for use with `Parser.read_element` and `Writer.write_element` for
/// handling ASN.1 `PrintableString`.  A `PrintableString` contains an `&str`
/// with only valid characers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrintableString<'a>(&'a str);

impl<'a> PrintableString<'a> {
    pub fn new(s: &'a str) -> Option<PrintableString<'a>> {
        if PrintableString::verify(s.as_bytes()) {
            Some(PrintableString(s))
        } else {
            None
        }
    }

    fn new_from_bytes(s: &'a [u8]) -> Option<PrintableString<'a>> {
        if PrintableString::verify_loosely(s) {
            Some(PrintableString(core::str::from_utf8(s).unwrap()))
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &'a str {
        self.0
    }

    fn verify_loosely(data: &[u8]) -> bool {
        for b in data {
            match b {
                b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b' '
                | b'\''
                | b'('
                | b')'
                | b'+'
                | b','
                | b'-'
                | b'.'
                | b'/'
                | b':'
                | b'='
                | b'?'
                // The * & _ are used by some ca.
                // So we need to allow it.
                | b'*' 
                | b'&'
                | b'_' => {}
                _ => return false,
            };
        }
        true
    }

    fn verify(data: &[u8]) -> bool {
        for b in data {
            match b {
                b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b' '
                | b'\''
                | b'('
                | b')'
                | b'+'
                | b','
                | b'-'
                | b'.'
                | b'/'
                | b':'
                | b'='
                | b'?' => {}
                _ => return false,
            };
        }
        true
    }
}

impl<'a> asn1::SimpleAsn1Readable<'a> for PrintableString<'a> {
    const TAG: asn1::Tag = asn1::Tag::primitive(0x13);
    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        PrintableString::new_from_bytes(data)
            .ok_or_else(|| asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue))
    }
}

impl asn1::SimpleAsn1Writable for PrintableString<'_> {
    const TAG: asn1::Tag = asn1::Tag::primitive(0x13);
    fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
        dest.push_slice(self.0.as_bytes())
    }
}