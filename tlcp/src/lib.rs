#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(slice_as_chunks)]

use std::io;

use opengm_crypto::cryptobyte;
mod common;
mod cipher_suits;
mod conn;
mod consts;
// pub mod encoding;
pub mod x509;
mod prf;
mod record;
mod messages;
mod handshake_client;
mod handshake_server;
mod key_agreement;
mod config;
mod utils;
mod traits;
mod finished_hash;
mod crypto_engine;
mod client;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("io error")]
    Io(#[from] io::Error),
    
    #[error("generate random number failed")]
    RandomNumber(#[from] rand::Error),

    #[error("Encoding error, caused by {0}")]
    Encoding(#[from] cryptobyte::Error),

    #[error("failed to found supported cipher suite")]
    NoCipherSuiteFound,

    #[error("Invalid handshake message")]
    InvalidHandshakeMsg,

    #[error("Invalid record message {}", .0)]
    InvalidRecordMsg(u8),

    #[error("Invalid alert level {}", .0)]
    InvalidAlertLevel(u8),

    #[error("Invalid alert message {}", .0)]
    InvalidAlertMsg(u8),

    #[error("Unknown handshake message type {}", .0)]
    UnknownHandShakeMsgType(u8),

    #[error("unexpected message")]
    UnexpectedMessage,

    #[error("alert: {}", .0)]
    Alert(&'static str),

    #[error("Server's certs has different type public key with cipher suite.")]
    ServerPublicKeyTypeUnmatch,   // TODO: add parameters.

    #[error("decode sm2 signature failed")]
    DecodeSM2SignatureFailure,

    #[error("decode sm2 public key failed")]
    DecodeSM2PublicFailure,

    #[error("verify server signature failed")]
    VerifyServerKeyExchangeFailed,

    #[error("no key agreement found")]
    NoKeyAgreementAvailable,

    #[error("cbc crypt failed, caused by \"{0}\"")]
    CBCModeCryptError(#[from] opengm_crypto::blockmode::Error),
    
    #[error("internal error")]
    InternalError,

    #[error("unknown error")]
    Unknown,
}

impl Default for Error {
    fn default() -> Self {
        return Error::Unknown;
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn test_error(){
        println!("{}", Error::CBCModeCryptError(opengm_crypto::blockmode::Error::InvalidInputSize));
    }
}