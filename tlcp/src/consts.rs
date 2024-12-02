pub const VERSION_TLCP: u16 = 0x0101;
pub const VERSION_TLS10: u16 = 0x0301;
pub const VERSION_TLS11: u16 = 0x0302;
pub const VERSION_TLS12: u16 = 0x0303;
pub const VERSION_TLS13: u16 = 0x0304;

// TLS compression types.
pub const COMPRESSION_NONE: u8 = 0;

// A list of cipher suite IDs that are, or have been, implemented by this
// package.
//
// See https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
// TLS 1.0 - 1.2 cipher suites.
pub const TLS_RSA_WITH_RC4_128_SHA: u16 = 0x0005;
pub const TLS_RSA_WITH_3DES_EDE_CBC_SHA: u16 = 0x000a;
pub const TLS_RSA_WITH_AES_128_CBC_SHA: u16 = 0x002f;
pub const TLS_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0035;
pub const TLS_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x003c;
pub const TLS_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009c;
pub const TLS_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009d;
pub const TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: u16 = 0xc007;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: u16 = 0xc009;
pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: u16 = 0xc00a;
pub const TLS_ECDHE_RSA_WITH_RC4_128_SHA: u16 = 0xc011;
pub const TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: u16 = 0xc012;
pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0xc013;
pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0xc014;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: u16 = 0xc023;
pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: u16 = 0xc027;
pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;
pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xc030;
pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xc02c;
pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca8;
pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca9;

// TLS 1.3 cipher suites.
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
// that the client is doing version fallback. See RFC 7507.
pub const TLS_FALLBACK_SCSV: u16 = 0x5600;

// Legacy names for the corresponding cipher suites with the correct _SHA256
// suffix, retained for backward compatibility.
pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305: u16 =
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305: u16 =
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;

// Defined in GB/T 38636 TLCP 1.1.
pub const TLCP_ECDHE_SM4_CBC_SM3: u16 = 0xe011;
pub const TLCP_ECDHE_SM4_GCM_SM3: u16 = 0xe051;
pub const TLCP_IBSDH_SM4_CBC_SM3: u16 = 0xe015;
pub const TLCP_IBSDH_SM4_GCM_SM3: u16 = 0xe055;

// Client generate pre master key and encrypt it by the ECC/IBC/RSA public key of server,
// sends the cipher to server.
pub const TLCP_ECC_SM4_CBC_SM3: u16 = 0xe013;
pub const TLCP_ECC_SM4_GCM_SM3: u16 = 0xe053;
pub const TLCP_IBC_SM4_CBC_SM3: u16 = 0xe017;
pub const TLCP_IBC_SM4_GCM_SM3: u16 = 0xe057;
pub const TLCP_RSA_SM4_CBC_SM3: u16 = 0xe019;
pub const TLCP_RSA_SM4_GCM_SM3: u16 = 0xe059;
pub const TLCP_RSA_SM4_CBC_SHA256: u16 = 0xe01c;
pub const TLCP_RSA_SM4_GCM_SHA256: u16 = 0xe05a;
pub const TLCP_UNKNOWN: u16 = 0;

pub fn is_dhe(cipher_suit: u16) -> bool {
    match cipher_suit {
        TLCP_ECDHE_SM4_CBC_SM3
        | TLCP_ECDHE_SM4_GCM_SM3
        | TLCP_IBSDH_SM4_CBC_SM3
        | TLCP_IBSDH_SM4_GCM_SM3 => true,
        _ => false,
    }
}
