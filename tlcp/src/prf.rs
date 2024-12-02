use opengm_crypto::{hmac_sm3_into, sm3};

const MASTER_SECRET: &[u8] = "master secret".as_bytes();
const CLIENT_FINISHED:&[u8] = "client finished".as_bytes();
const SERVER_FINISHED:&[u8] = "server finished".as_bytes();
const KEY_EXPANSION: &[u8] = "key expansion".as_bytes();
const MASTER_SECRET_LENGTH:usize = 48;
const FINISHED_LENGTH :usize = 12;

macro_rules! phash_sm3 {
    ($out:expr, $secret:expr, $($seeds:expr),+ $(,)?) => {{
        let N = $out.len();
        let mut mac =[0; sm3::DIGEST_SIZE];
        let mut a =[0; sm3::DIGEST_SIZE];
        hmac_sm3_into!(&mut a, $secret, $($seeds),+); //a1
        
        let num_of_exact_chunks = N & (!(sm3::DIGEST_SIZE-1));
        for chunk in $out[..num_of_exact_chunks].chunks_exact_mut(sm3::DIGEST_SIZE) {
            hmac_sm3_into!(chunk, $secret, &a, $($seeds),+);
            hmac_sm3_into!(&mut mac, $secret, &a);
            a = mac;
        }

        let remainder = N % sm3::DIGEST_SIZE;
        if remainder > 0{
            hmac_sm3_into!(&mut mac, $secret, &a, $($seeds),+);
            $out[num_of_exact_chunks..].copy_from_slice(&mac[..N - num_of_exact_chunks]);
        }
    }};
}

macro_rules! prf_sm3{
    ($out:expr, $secret:expr, $label:expr, $($seeds:expr),+ $(,)?) => {{
        phash_sm3!($out, $secret, $label, $($seeds),+);
    }};
}

#[inline]
pub fn compute_master_secret(pre_master_secret: &[u8], client_random: &[u8], server_random: &[u8])-> [u8;MASTER_SECRET_LENGTH] {
    let mut master_secret = [0;MASTER_SECRET_LENGTH];
    prf_sm3!(&mut master_secret, pre_master_secret, MASTER_SECRET, client_random, server_random);
    master_secret
}

#[inline]
pub fn compute_finished_verify_data(master_secret: &[u8], handshake_msg_hash: &[u8], is_client: bool)-> [u8; FINISHED_LENGTH] {
    let mut out = [0u8;FINISHED_LENGTH];
    if is_client{
        prf_sm3!(out, master_secret, CLIENT_FINISHED, handshake_msg_hash);
    }else{
        prf_sm3!(out, master_secret, SERVER_FINISHED, handshake_msg_hash);
    }
    out
}

#[derive(Debug, Default)]
pub struct KeyBlock {
    pub client_write_mac_key: Vec<u8>,
    pub server_write_mac_key: Vec<u8>,

    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,

    pub client_write_IV: Vec<u8>,
    pub server_write_IV: Vec<u8>,
}

impl KeyBlock {
    pub fn new(master_secret: &[u8], client_random: &[u8], server_random: &[u8], mac_size: usize, key_length: usize, iv_length: usize) -> Self {
        let mut key = vec![0u8; 2 * (mac_size + key_length + iv_length)];
        prf_sm3!(&mut key, master_secret, KEY_EXPANSION, server_random, client_random);
        KeyBlock {
            client_write_mac_key: key[..mac_size].to_owned(),
            server_write_mac_key: key[mac_size..2 * mac_size].to_owned(),
            client_write_key: key[2 * mac_size..2 * mac_size + key_length].to_owned(),
            server_write_key: key[2 * mac_size + key_length..2 * (mac_size + key_length)].to_owned(),
            client_write_IV: key[2 * (mac_size + key_length)..2 * (mac_size + key_length) + iv_length].to_owned(),
            server_write_IV: key[2 * (mac_size + key_length) + iv_length..2 * (mac_size + key_length + iv_length)].to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use opengm_crypto::{hmac_sm3_into, sm3};

    #[test]
    fn test_prf() {
        let secret = [1;4];
        let label = [1;4];
        let seed = [1;4];
        let mut out = [0; 12];
        prf_sm3!(&mut out, &secret, &label, &seed);
        assert_eq!(out, hex!("3323fa666a90325bc1b55198"))
    }
}
