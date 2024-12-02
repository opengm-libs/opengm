use core::borrow;

use crate::messages::{HandshakeMsgType, HANDSHAKD_HEADER_LENGTH};
use opengm_crypto::cryptobyte::{Builder, Parser, parser::AsParser};
use crate::{Result, Error};

const MSG_TYPE:HandshakeMsgType = HandshakeMsgType::CertificateVerify;

#[derive(Debug, Default)]
pub struct CertificateVerifyMsg {}