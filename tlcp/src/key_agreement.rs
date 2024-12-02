use crate::consts::{is_dhe, TLCP_ECC_SM4_CBC_SM3, TLCP_ECC_SM4_GCM_SM3};
use crate::crypto_engine::SM2Engine;
use opengm_crypto::cryptobyte::parser::AsParser;
use opengm_crypto::cryptobyte::{Builder, Parser};
use opengm_crypto::cms::sm2::{encode_sm2_cipher, ASN1Decode};
use crate::messages::*;
use crate::{
    messages::{ClientHelloMsgOwned, ServerHelloMsgBorrowed},
    x509::{Certificate, PublicKeyAlgorithm},
};
use crate::{x509, Error, Result};
use num::bigint::Sign;
use num::BigInt;
use opengm_crypto::{sm2, sm3};
use rand::rngs::ThreadRng;
use rand::{thread_rng, Rng, RngCore};

/*
enum {ECDHE，ECC,IBSDH,IBC,RSA} KeyExchangeAlgorithm;
struct {
    select (KeyExchangeAlgorithm){
    case ECDHE:
        ServerECDHEParams params;
            digitally-signed struct {
            opaque client_random[32];
            opaque server_random[32];
            ServerECDHEParams params;
        } signed_params;
    case ECC:
        digitally-signed struct {
            opaque client_random[32];
            opaque server_random[32];
            opaque ASN.1Cert<1..2^24-1>;
        } signed_params;
    case IBSDH:
        ServerIBSDHParams params;
        digitally-signed struct {
            opaque client_random[32];
            opaque server_random[32];
            ServerIBSDHParams params;
        } signed_params;
    case IBC:
        digitally-signed struct {
            opaque client_random[32];
            opaque server_random[32];
            opaque ibc_id<1..2^16-1>;
        } signed_params;
    case RSA:
        digitally-signed struct {
            opaque client_random[32];
            opaque server_random[32];
            opaque ASN.1Cert<1..2^24-1>;
        } signed_params;
    }
} ServerKeyExchange;


struct {
    select (KeyExchangeAlgorithm) {
    case ECDHE:
        Opaque ClientECDHEParams<1..2^16-1>;
    case IBSDH:
        Opaque ClientIBSDHParams<1..2^16-1>;
    case ECC:
        opaque ECCEncryptedPreMasterSecret<0..2^16-1>;
    case IBC:
        opaque IBCEncryptedPreMasterSecret<0..2^16-1>;
    case RSA:
        opaque RSAEncryptedPreMasterSecret<0..2^16-1>;
    } exchange_keys;
} ClientKeyExchange;
*/

// client side key agreement
pub trait ClientKeyAgreement {
    fn process_server_key_exchange(
        &mut self,
        client_hello: &ClientHelloMsgOwned,
        server_hello: &ServerHelloMsgBorrowed,
        skx: &ServerKeyExchangeMsgBorrowed,
        server_cert: &Certificate,
    ) -> Result<()>;
    fn generate_client_key_exchange(
        &self,
    ) -> Result<([u8; 48], ClientKeyExchangeMsgOwned)>;
}

// server side key agreement
pub trait ServerKeyAgreement {
    fn generate_server_key_exchange(
        &self,
        cipher_suit: u16,
        client_hello: &ClientHelloMsgBorrowed,
        server_hello: &ServerHelloMsgOwned,
    ) -> ServerKeyExchangeMsgOwned;

    // Returns the pre-master secret.
    fn process_client_key_exchange(
        &self,
        cipher_suit: u16,
        ckx: &ClientKeyExchangeMsgBorrowed,
    ) -> Result<[u8;48]>;
}

pub fn get_client_key_agreement(
    cipher_suit: u16,
    server_enc_cert: x509::Certificate,
) -> Option<Box<dyn ClientKeyAgreement>> {
    match cipher_suit {
        TLCP_ECC_SM4_CBC_SM3 | TLCP_ECC_SM4_GCM_SM3 => {
            Some(Box::new(ClientKeyAgreementECC {
                server_enc_cert: server_enc_cert,
            }))
        }
        _ => None,
    }
}

pub fn new_client_key_agreement_ecc(
    server_enc_cert: x509::Certificate,
) -> Box<dyn ClientKeyAgreement> {
    Box::new(ClientKeyAgreementECC { server_enc_cert })
}

// Client key agreement for cipher suite TLCP_ECC_SM4_CBC_SM3/TLCP_ECC_SM4_GCM_SM3
pub struct ClientKeyAgreementECC {
    // pub hmac: HMacSM3,
    // pub cbc: CBCMode<sm4::Cipher>,
    pub server_enc_cert: x509::Certificate,
}
impl ClientKeyAgreement for ClientKeyAgreementECC {
    // ClientKeyExchange:
    // opaque ECCEncryptedPreMasterSecret<0..2^16-1>;
    fn generate_client_key_exchange(
        &self,
    ) -> Result<([u8; 48], ClientKeyExchangeMsgOwned)> {
        let mut rng: ThreadRng = thread_rng();
        let mut pre_master_key = [0; 48];
        let mut k = [0u64; 4];
        pre_master_key[0] = 1;
        pre_master_key[1] = 1;
        rng.fill_bytes(&mut pre_master_key[2..]);
        rng.fill(&mut k);

        let ciphertext = sm2::encrypt(
            self.server_enc_cert
                .public_key
                .downcast_ref::<sm2::PublicKey>()
                .unwrap(),
            &pre_master_key,
            &k,
        );
        let ciphertext = encode_sm2_cipher(&ciphertext).unwrap();
        let client_key_exchange = ClientKeyExchangeMsgOwned::new(ciphertext);
        Ok((pre_master_key, client_key_exchange))
    }

    // ServerKeyExchangeMsg:
    // digitally-signed struct {
    //     opaque client_random[32];
    //     opaque server_random[32];
    //     opaque ASN.1Cert<1..2^24-1>; -- server enc cert
    //  } signed_params; -- signed by server sign cert.
    fn process_server_key_exchange(
        &mut self,
        client_hello: &ClientHelloMsgOwned,
        server_hello: &ServerHelloMsgBorrowed,
        skx: &ServerKeyExchangeMsgBorrowed,
        server_sign_cert: &Certificate,
    ) -> Result<()> {
        // verify the signature
        if server_sign_cert.public_key_algorithm != PublicKeyAlgorithm::ECC {
            return Err(Error::ServerPublicKeyTypeUnmatch);
        }
        let public_key = server_sign_cert
            .public_key
            .downcast_ref::<sm2::PublicKey>()
            .ok_or(Error::ServerPublicKeyTypeUnmatch)?;
        let z = sm2::precompute_with_id_public_key(None, public_key);

        let mut d = sm3::Digest::new();
        d.write(&z);
        d.write(&client_hello.random);
        d.write(&server_hello.random);

        let enc_cert = self.server_enc_cert.bytes();
        d.write(&[
            (enc_cert.len() >> 16) as u8,
            (enc_cert.len() >> 8) as u8,
            (enc_cert.len() >> 0) as u8,
        ]);
        d.write(enc_cert);
        let e = d.sum();

        let mut parser = Parser::new(skx.key);
        let signature = parser
            .read_u16_length_prefixed()
            .ok_or(Error::DecodeSM2SignatureFailure)?
            .as_parser()
            .decode_sm2_signature()
            .ok_or(Error::DecodeSM2SignatureFailure)?;

        if sm2::verify(&e, public_key, &signature) {
            Ok(())
        } else {
            Err(Error::VerifyServerKeyExchangeFailed)
        }
    }
}

impl ServerKeyAgreement for SM2Engine {
    fn generate_server_key_exchange(
        &self,
        cipher_suit: u16,
        client_hello: &ClientHelloMsgBorrowed,
        server_hello: &ServerHelloMsgOwned,
    ) -> ServerKeyExchangeMsgOwned {
        if is_dhe(cipher_suit) {
            todo!()
        } else {
            let public_key = self.sign_key.public();
            let z = sm2::precompute_with_id_public_key(None, &public_key);
            let mut d = sm3::Digest::new();
            d.write(&z);
            d.write(&client_hello.random);
            d.write(&server_hello.random);

            let enc_cert = &self.certificates[1];
            d.write(&[
                (enc_cert.len() >> 16) as u8,
                (enc_cert.len() >> 8) as u8,
                (enc_cert.len() >> 0) as u8,
            ]);
            d.write(enc_cert);
            let e = d.sum();
            let signature =
                sm2::sign(&e, &self.sign_key, &mut thread_rng()).unwrap();

            let mut b = Builder::new(Vec::new());
            b.add_u16_length_prefixed(|b| {
                b.add_asn1_sequence(|b| {
                    b.add_asn1_bigint(&BigInt::from_bytes_be(
                        Sign::Plus,
                        &signature.r.to_be_bytes(),
                    ));
                    b.add_asn1_bigint(&BigInt::from_bytes_be(
                        Sign::Plus,
                        &signature.s.to_be_bytes(),
                    ));
                });
            });
            ServerKeyExchangeMsgOwned {
                raw: None,
                key: b.take().unwrap(),
            }
        }
    }

    
    fn process_client_key_exchange(&self,
        cipher_suit: u16,
        ckx: &ClientKeyExchangeMsgBorrowed,
    ) -> Result<[u8;48]>{
        if is_dhe(cipher_suit) {
            todo!()
        } else {
            let cipher = Parser::new(ckx.ciphertext)
            .decode_sm2_cipher()
            .ok_or(Alert::DecodeError)?;
          if let Ok(key) = sm2::decrypt(&self.enc_key, &cipher){
           Ok(key)
          }else{
            Err(Alert::DecryptError.into())
          }
        }
    }
}

// key agreement for cipher suites
// - TLCP_RSA_SM4_CBC_SM3
// - TLCP_RSA_SM4_GCM_SM3
// - TLCP_RSA_SM4_CBC_SHA256
// - TLCP_RSA_SM4_GCM_SHA256

// impl<'a> CBCEncrypter<'a> {
//     pub fn new(key: &[u8])->Self{
//         let block = Box::new(Cipher::new(key));
//         let mut res = CBCEncrypter{
//             block: block,
//             mode: Box::new(CBCMode::new(block.as_ref())),
//         };
//         res.mode = Box::new(&*res.block);
//         res
//     }
// }
