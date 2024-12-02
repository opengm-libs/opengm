
use num::{bigint::Sign, BigInt};
use opengm_crypto::sm2;
use rand::{thread_rng, Rng, RngCore};
use opengm_crypto::cryptobyte::{asn1::BitString, oid::OidSignatureSM2WithSM3, Builder};


// A cryptoModule provides sign/enc and certificates for TLCP
pub trait CryptoEngine{
    // returns the certificate (chain)
    fn certificates(&self) -> &Vec<Vec<u8>>;
    fn sign(&self, plain: &[u8]) -> Result<Vec<u8>>;
    fn encrypt(&self, plain: &[u8]) -> Result<Vec<u8>>;
    fn generate_random(b: &mut [u8]) -> Result<()>;
}


#[derive(thiserror::Error, Debug)]
pub enum Error {}
pub type Result<T> = core::result::Result<T, Error>;

pub struct SM2Engine{
    pub rng: Box<dyn RngCore>,
    pub sign_key: sm2::PrivateKey,
    pub enc_key: sm2::PrivateKey,
    pub certificates: Vec<Vec<u8>>,
}

impl SM2Engine{
    pub fn new(rng: Box<dyn RngCore>) -> Self{
        let mut rng = rng;
        let sign_key = sm2::PrivateKey::new(&mut rng);
        let enc_key = sm2::PrivateKey::new(&mut rng);
        let mut certificates = Vec::with_capacity(2);
        certificates.push(make_sm2_certificate(&sign_key));
        certificates.push(make_sm2_certificate(&enc_key));
        SM2Engine{
            rng: rng,
            sign_key,
            enc_key,
            certificates,
        }
    }
}


impl CryptoEngine for SM2Engine{
    fn certificates(&self) -> &Vec<Vec<u8>> {
        return &self.certificates;
    }

    fn sign(&self, plain: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }

    fn encrypt(&self, plain: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }
    
    fn generate_random(b: &mut [u8]) -> Result<()> {
        todo!()
    }
}


// make a certificate just containing the key, only for development.
pub fn make_sm2_certificate(key: &sm2::PrivateKey) -> Vec<u8>{
    let mut b = Builder::new(Vec::new());
    // 04 || x || y
    let mut key_info = [0;65];
    key_info[0] = 4;
    key_info[1..33].copy_from_slice(&key.public().x.to_be_bytes());
    key_info[33..].copy_from_slice(&key.public().y.to_be_bytes());



    // tbs
    b.add_asn1_sequence(|b|{
        // version omit
        
        // serial number
        b.add_asn1_bigint(&BigInt::new(Sign::Plus, vec![1,2,3,4]));

        // algorithm_identifier
        b.add_asn1_sequence(|_b|{});
    
        // issuer = tbs_certificate.read_asn1_sequence()?;
        b.add_asn1_sequence(|_b|{});

        // validity
        b.add_asn1_sequence(|_b|{});

        // subject
        b.add_asn1_sequence(|_b|{});

    
        // let mut subject_public_key_info = tbs_certificate.read_asn1_sequence()?;
        b.add_asn1_sequence(|b|{
            b.add_asn1_sequence(|b|{
                b.add_asn1_object_identifier(&OidSignatureSM2WithSM3.into());
            });
            b.add_asn1_bit_string(&BitString::new(key_info, key_info.len() * 8));
        });
    });
    let tbs_certificate = b.take().unwrap();

    let e = sm2::precompute_with_id_public_key_msg(None, &key.public(), &tbs_certificate);
    let signature = sm2::sign(&e, key, &mut thread_rng()).unwrap();
    let r = BigInt::from_bytes_be(Sign::Plus,&signature.r.to_be_bytes());
    let s = BigInt::from_bytes_be(Sign::Plus,&signature.s.to_be_bytes());
    
    let mut b = Builder::new(Vec::new());
    b.add_asn1_sequence(|b|{
        b.add_bytes(&tbs_certificate);
        b.add_asn1_sequence(|b|{
            b.add_asn1_object_identifier(&OidSignatureSM2WithSM3.into());
        });
        b.add_asn1_sequence(|b|{
            b.add_asn1_bigint(&r);
            b.add_asn1_bigint(&s);
        });
    });
    b.take().unwrap()
}