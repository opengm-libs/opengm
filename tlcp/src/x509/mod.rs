use std::any::Any;

pub mod algorithm_identifier;
pub mod certificate;
pub mod errors;
pub mod oid;
mod print_string;
mod asn1_test;
pub(crate) mod name;
mod asn1_cert;
mod extension;
mod util;
mod types;

pub use util::*;

#[derive(Debug, PartialEq, Eq)]
pub enum PublicKeyAlgorithm {
    Unknown = 0,
    RSA = 1,
    ECC = 2, // i.e., SM2
    IBC = 3, // i.e., SM9
}

pub struct Certificate {
    // TODO: use &[u8] to avoid memory copy.
    pub raw: Vec<u8>,
    pub public_key_algorithm: PublicKeyAlgorithm,
    pub public_key: Box<dyn Any>,
}

impl Certificate{
    pub fn bytes(&self) -> &[u8]{
        self.raw.as_ref()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test1() {
        // let data = b"\x30\x06\x02\x01\x01\x02\x01\x03";

        // let result: asn1::ParseResult<_> = asn1::parse(data, |d| d.read_element::<asn1::Sequence>()?.parse(|d| Ok((d.read_element::<i64>()?, d.read_element::<i64>()?))));

        // // Using libc::printf because println! isn't no_std!
        // match result {
        //     Ok((r, s)) => println!("r={}, s={}\n\x00", r, s),
        //     Err(_) => println!("Error\n\x00"),
        // };

        // let computed = asn1::write(|w| {
        //     w.write_element(&asn1::SequenceWriter::new(&|w: &mut asn1::Writer| {
        //         w.write_element(&1i64)?;
        //         w.write_element(&3i64)?;
        //         Ok(())
        //     }))
        // })
        // .unwrap();
        // println!("Original length: {}\nComputed length: {}", data.len(), computed.len(),);
    }
}
