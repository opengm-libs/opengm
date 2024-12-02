use std::io;

use opengm_crypto::cryptobyte;


#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("io error")]
    Io(#[from] io::Error),

    #[error("Encoding error")]
    Encoding(#[from] cryptobyte::Error),

    #[error("verify sm2 signature error")]
    SM2Verify,
}

pub type Result<T> = std::result::Result<T, Error>;
