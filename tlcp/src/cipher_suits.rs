use crate::{consts::TLCP_ECC_SM4_GCM_SM3, traits::*};

use opengm_crypto::{
    blockmode::{cbc::CBCMode, gcm::GCM}, mac::HMacSM3, sm4, traits::{Block, AEAD}
};

use crate::{
    consts::TLCP_ECC_SM4_CBC_SM3,
    key_agreement::{new_client_key_agreement_ecc, ClientKeyAgreement},
    x509, Error, Result,
};

#[derive(Clone, Copy)]
pub enum CipherSuiteFlag {
    // flags
    // suiteECDHE indicates that the cipher suite involves elliptic curve
    // Diffie-Hellman. This means that it should only be selected when the
    // client indicates that it supports ECC with a curve and point format
    // that we're happy with.
    SuiteECDHE = 1,
    // suiteECSign indicates that the cipher suite involves an ECDSA or
    // EdDSA signature and therefore may only be selected when the server's
    // certificate is ECDSA or EdDSA. If this is not set then the cipher suite
    // is RSA based.
    SuiteECSign = 2,
    // suiteTLS12 indicates that the cipher suite should only be advertised
    // and accepted when using TLS 1.2.
    SuiteTLS12 = 4,
    // suiteSHA384 indicates that the cipher suite uses SHA384 as the
    // handshake hash.
    // suiteSHA384

    // suiteTLCP indicates that only TLCP cipher suite.
    SuiteTLCP = 8,
    // suiteDefaultOff indicates that this cipher suite is not included by
    // default.
    // suiteDefaultOff
    SuitRSA = 16,
    SuiteIBC = 32,
    SuiteIBSDH = 64,

    IsMacThenEnc = 128,
    IsAead = 256,
    // suiteSM2 = suiteECSign | suiteECDHE
    // suiteSM9 = suiteIBC | suiteIBSDH
}

impl CipherSuiteFlag {
    #[inline]
    pub(crate) fn have(self, flag: CipherSuiteFlag) -> bool {
        ((self as u32) & (flag as u32)) != 0
    }
}

// A cipherSuite is a specific combination of key agreement, cipher and MAC function.
#[derive(Clone, Copy)]
pub(crate) struct CipherSuite {
    pub id: u16,
    // the lengths, in bytes, of the key material needed for each component.
    pub key_len: usize,
    pub mac_len: usize,
    pub iv_len: usize,

    // flags is a bitmask of the suite* values, above.
    pub flags: CipherSuiteFlag,

    pub client_ka: fn(x509::Certificate) -> Box<dyn ClientKeyAgreement>,

    // isRead: true for Decrypte.
    pub enc: fn(key: &[u8], is_read: bool) -> Option<Box<dyn TlcpEnc>>,
    pub mac: fn(key: &[u8]) -> Option<Box<dyn TlcpMac>>,
    pub aead: fn(key: &[u8], fixed_nonce: &[u8], is_read: bool) -> Option<Box<dyn TlcpAead>>,
}

const CipherSuites: [CipherSuite; 2] = [
    CipherSuite {
        id: TLCP_ECC_SM4_CBC_SM3,
        key_len: 16,
        mac_len: 32,
        iv_len: 0,
        flags: CipherSuiteFlag::IsMacThenEnc,

        client_ka: new_client_key_agreement_ecc,

        enc: new_sm4_cbc_cipher,
        mac: new_hmac_sm3,
        aead: no_aead,
    },
    CipherSuite {
        id: TLCP_ECC_SM4_GCM_SM3,
        key_len: 16,
        mac_len: 0,
        iv_len: 4,
        flags: CipherSuiteFlag::IsAead,

        client_ka: new_client_key_agreement_ecc,

        enc: no_enc,
        mac: no_mac,
        aead: new_sm4_aead,
    },
];

impl TryFrom<u16> for CipherSuite {
    type Error = Error;
    fn try_from(id: u16) -> Result<Self> {
        for cipher_suite in &CipherSuites {
            if cipher_suite.id == id {
                return Ok(*cipher_suite);
            }
        }
        Err(Error::NoCipherSuiteFound)
    }
}
impl CipherSuite {
    #[inline]
    pub fn is_aead(&self) -> bool {
        self.flags.have(CipherSuiteFlag::IsAead)
    }
}

// selectCipherSuite returns the first cipher suite from ids which is also in
// supportedIDs and passes the ok filter.
// Server uses this to choose the first cipher suite in common.
pub(crate) fn select_cipher_suite(ids: &[u16], supported_ids: &[u16], ok: fn(&CipherSuite) -> bool) -> Result<CipherSuite> {
    for id in ids {
        let cipher_suite = CipherSuite::try_from(*id)?;
        if ok(&cipher_suite) && supported_ids.contains(id) {
            return Ok(cipher_suite);
        }
    }
    Err(Error::NoCipherSuiteFound)
}

/**************************************************************
 *
 * SM3 HMAC 
 *
 **************************************************************/


fn new_hmac_sm3(key: &[u8]) -> Option<Box<dyn TlcpMac>> {
    Some(Box::new(HMacSM3::new(key)))
}

impl TlcpMac for HMacSM3 {
    fn reset(&mut self) {
        HMacSM3::reset(self);
    }

    fn write(&mut self, data: &[u8]) {
        HMacSM3::write(self, data);
    }

    fn sum_into(&mut self, mac: &mut [u8]) {
        HMacSM3::sum_into(self, mac);
    }

    fn mac_size(&self) -> usize {
        32
    }
}

/**************************************************************
 *
 * SM4 CBC
 *
 **************************************************************/


pub struct CBCCipher<B: Block> {
    block_mode: CBCMode<B>,
    is_read: bool,
}

impl<B: Block> TlcpEnc for CBCCipher<B> {
    fn block_size(&self) -> usize {
        self.block_mode.block_size
    }

    fn crypt_blocks(&self, iv: &[u8], in_out: &mut [u8]) -> Result<()> {
        if self.is_read {
            self.block_mode.decrypt_inplace(iv, in_out)?;
        } else {
            self.block_mode.encrypt_inplace(iv, in_out)?;
        }
        Ok(())
    }
}

pub fn new_sm4_cbc_cipher(key: &[u8], is_read: bool) -> Option<Box<dyn TlcpEnc>> {
    Some(Box::new(CBCCipher {
        block_mode: CBCMode::new(sm4::Cipher::new(&key)),
        is_read,
    }))
}

/**************************************************************
 *
 * SM4 AEAD
 *
 **************************************************************/

pub struct AEADCipher<B: Block> {
    nonce: [u8; STD_NONCE_SIZE],
    gcm: GCM<B, STD_NONCE_SIZE, STD_TAG_SIZE>,
    is_read: bool,
}

impl<B: Block> TlcpAead for AEADCipher<B> {
    fn seal(&mut self, in_out: &mut [u8], tag: &mut [u8], explicite_nonce: &[u8], add: &[u8]) -> Result<()> {
        self.nonce[STD_FIXED_NONCE_SIZE..].copy_from_slice(explicite_nonce);
        Ok(self.gcm.seal_inplace(in_out, tag, &self.nonce, Some(add))?)
    }

    fn open(&mut self, in_out: &mut [u8], tag: &[u8], explicite_nonce: &[u8], add: &[u8]) -> Result<()> {
        self.nonce[STD_FIXED_NONCE_SIZE..].copy_from_slice(explicite_nonce);
        Ok(self.gcm.open_inplace(in_out,tag, &self.nonce, Some(add))?)
    }
}

pub fn new_sm4_aead(key: &[u8], fexed_nonce: &[u8], is_read: bool) -> Option<Box<dyn TlcpAead>> {
    let mut ac = Box::new(AEADCipher {
        gcm: GCM::new(sm4::Cipher::new(&key)),
        is_read: is_read,
        nonce: [0;STD_NONCE_SIZE],
    });
    ac.nonce[0] = fexed_nonce[0];
    ac.nonce[1] = fexed_nonce[1];
    ac.nonce[2] = fexed_nonce[2];
    ac.nonce[3] = fexed_nonce[3];

    Some(ac)
}

// default implementation

fn no_ka(_: x509::Certificate) -> Box<dyn ClientKeyAgreement> {
    unreachable!()
}

fn no_enc(_: &[u8], _: bool) -> Option<Box<dyn TlcpEnc>> {
    None
}
fn no_mac(_: &[u8]) -> Option<Box<dyn TlcpMac>> {
    None
}
fn no_aead(_: &[u8], _: &[u8], _: bool) -> Option<Box<dyn TlcpAead>> {
    None
}
