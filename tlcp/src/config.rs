use std::{cell::RefCell, rc::Rc};

use rand::{thread_rng, RngCore};

use crate::{consts::*, crypto_engine::SM2Engine, x509::{Certificate, PublicKeyAlgorithm}};
use opengm_crypto::sm2::{PublicKey, U256};

pub struct CertificatesChain{
    raw: Option<Vec<u8>>,
    certificates: Vec<Certificate>,
}
impl CertificatesChain {
    pub fn bytes(&mut self) -> &[u8] {
        // if self.
        self.raw.as_ref().unwrap()
    }
    
}

pub struct Config{
    pub version: u16,
    supported_versions: Vec<u16>,
    supported_cipher_suites: Vec<u16>,

    // encode certificates
    certificates_chain: RefCell<CertificatesChain>,

    pub rng: Rc<RefCell<Box<dyn RngCore>>>,
    // 
    pub crypto: Option<Box<SM2Engine>>,
}

fn default_cipher_suites()-> Vec<u16>{
    // if support gcm...
    vec![
        TLCP_ECC_SM4_CBC_SM3,
        TLCP_ECC_SM4_GCM_SM3,
    ]
}

impl Default for Config{
    fn default() -> Self {
        Self { 
            version: VERSION_TLCP,
            supported_versions: vec![VERSION_TLCP],
            supported_cipher_suites: default_cipher_suites(),
            rng: Rc::new(RefCell::new(Box::new(thread_rng()))),
            certificates_chain: RefCell::new(CertificatesChain{
                raw:None,
                certificates: vec![Certificate{ 
                    raw: Vec::new(), 
                    public_key_algorithm:PublicKeyAlgorithm::ECC, 
                    public_key: Box::new(PublicKey{ x: U256::default(), y: U256::default()}), 
                }],
            }),
            crypto: None,
        }
    }
}

impl Config{
    pub fn supported_versions(&self) -> &[u16]{
        &self.supported_versions
    }
    pub fn supported_cipher_suites(&self) -> &[u16]{
        &self.supported_cipher_suites
    }

    // returns the handshake message Certificate.
    // pub fn get_certificates(&mut self) -> &[u8]{
    //     self.certificates_chain.get_mut().bytes()
    // }
}
