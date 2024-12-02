use crate::Result;

pub use opengm_crypto::traits::Hash;

pub trait TlcpMac {
    fn mac_size(&self) -> usize;
    fn reset(&mut self);
    fn write(&mut self, data: &[u8]);
    fn sum_into(&mut self, mac: &mut [u8]);
}

pub trait TlcpEnc {
    fn block_size(&self) -> usize;
    fn crypt_blocks(&self, iv: &[u8], in_out: &mut [u8]) -> Result<()>;
}

pub const STD_TAG_SIZE:usize = 16;
pub const STD_FIXED_NONCE_SIZE:usize = 4;
pub const STD_EXPLICIT_NONCE_SIZE:usize = 8;
pub const STD_NONCE_SIZE:usize = STD_FIXED_NONCE_SIZE+STD_EXPLICIT_NONCE_SIZE;

pub trait TlcpAead {
    // TLCP中,由master_secret生成4字节的client_iv, server_iv.
    // nonce = client_iv/server_iv(4) + explicit_nonce(8).

    // NonceSize returns the size of the nonce that must be passed to Seal
    // and Open.
    // TLCP = 12,
    fn nonce_size(&self) -> usize {
        STD_NONCE_SIZE
    }

    fn fixed_nonce_size(&self) -> usize {
        STD_FIXED_NONCE_SIZE
    }

    // explicit_nonce_size returns the number of bytes of explicit nonce
    // included in each record.
    // TLCP: = 8, may use the 8 bytes of sequence num.
    // the explicit_nonce is contained in the application message.
    // struct {
    //      opaque nonce_explicit[SecurityParameters.record_iv_length];
    //      aead-ciphered struct {
    //          opaque content[TLSCompressed.length];
    //      };
    // } GenericAEADCipher;
    fn explicit_nonce_size(&self) -> usize {
        STD_EXPLICIT_NONCE_SIZE
    }

    // Overhead returns the maximum difference between the lengths of a
    // plaintext and its ciphertext.
    fn overhead(&self) -> usize{
        STD_TAG_SIZE
    }

    fn seal(&mut self, in_out: &mut [u8], tag: &mut [u8], explicite_nonce: &[u8], add: &[u8])->Result<()>;

    fn open(&mut self, in_out: &mut [u8], tag: &[u8],  explicite_nonce: &[u8], add: &[u8])-> Result<()>;
}