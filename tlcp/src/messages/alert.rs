use crate::{Error, Result};

// alert level
pub enum Level {
    Warning = 1,
    Fatal = 2,
}

impl TryFrom<u8> for Level {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Level::Warning),
            2 => Ok(Level::Fatal),
            _ => Err(Error::InvalidAlertLevel(value))
        }
    }
}

#[derive(Copy, Clone)]
pub enum Alert {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMAC = 20,
    DecryptionFailed = 21,
    RecordOverflow = 22,
    DecompressionFailure = 30,
    HandshakeFailure = 40,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCA = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ExportRestriction = 60,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    NoRenegotiation = 100,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    CertificateUnobtainable = 111,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    BadCertificateHashValue = 114,
    UnknownPSKIdentity = 115,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
}

impl TryFrom<u8> for Alert {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::CloseNotify),
            10 => Ok(Self::UnexpectedMessage),
            20 => Ok(Self::BadRecordMAC),
            21 => Ok(Self::DecryptionFailed),
            22 => Ok(Self::RecordOverflow),
            30 => Ok(Self::DecompressionFailure),
            40 => Ok(Self::HandshakeFailure),
            42 => Ok(Self::BadCertificate),
            43 => Ok(Self::UnsupportedCertificate),
            44 => Ok(Self::CertificateRevoked),
            45 => Ok(Self::CertificateExpired),
            46 => Ok(Self::CertificateUnknown),
            47 => Ok(Self::IllegalParameter),
            48 => Ok(Self::UnknownCA),
            49 => Ok(Self::AccessDenied),
            50 => Ok(Self::DecodeError),
            51 => Ok(Self::DecryptError),
            60 => Ok(Self::ExportRestriction),
            70 => Ok(Self::ProtocolVersion),
            71 => Ok(Self::InsufficientSecurity),
            80 => Ok(Self::InternalError),
            86 => Ok(Self::InappropriateFallback),
            90 => Ok(Self::UserCanceled),
            100 => Ok(Self::NoRenegotiation),
            109 => Ok(Self::MissingExtension),
            110 => Ok(Self::UnsupportedExtension),
            111 => Ok(Self::CertificateUnobtainable),
            112 => Ok(Self::UnrecognizedName),
            113 => Ok(Self::BadCertificateStatusResponse),
            114 => Ok(Self::BadCertificateHashValue),
            115 => Ok(Self::UnknownPSKIdentity),
            116 => Ok(Self::CertificateRequired),
            120 => Ok(Self::NoApplicationProtocol),
            _ => Err(Error::InvalidAlertMsg(value)),
        }
    }
}

impl Alert {
    pub fn level(self) -> Level {
        match self {
            Self::NoRenegotiation | Self::CloseNotify => Level::Warning,
            _ => Level::Fatal,
        }
    }
    pub fn string(self) -> &'static str {
        match self {
            Alert::CloseNotify => "close notify",
            Alert::UnexpectedMessage => "unexpected message",
            Alert::BadRecordMAC => "bad record MAC",
            Alert::DecryptionFailed => "decryption failed",
            Alert::RecordOverflow => "record overflow",
            Alert::DecompressionFailure => "decompression failure",
            Alert::HandshakeFailure => "handshake failure",
            Alert::BadCertificate => "bad certificate",
            Alert::UnsupportedCertificate => "unsupported certificate",
            Alert::CertificateRevoked => "revoked certificate",
            Alert::CertificateExpired => "expired certificate",
            Alert::CertificateUnknown => "unknown certificate",
            Alert::IllegalParameter => "illegal parameter",
            Alert::UnknownCA => "unknown certificate authority",
            Alert::AccessDenied => "access denied",
            Alert::DecodeError => "error decoding message",
            Alert::DecryptError => "error decrypting message",
            Alert::ExportRestriction => "export restriction",
            Alert::ProtocolVersion => "protocol version not supported",
            Alert::InsufficientSecurity => "insufficient security level",
            Alert::InternalError => "internal error",
            Alert::InappropriateFallback => "inappropriate fallback",
            Alert::UserCanceled => "user canceled",
            Alert::NoRenegotiation => "no renegotiation",
            Alert::MissingExtension => "missing extension",
            Alert::UnsupportedExtension => "unsupported extension",
            Alert::CertificateUnobtainable => "certificate unobtainable",
            Alert::UnrecognizedName => "unrecognized name",
            Alert::BadCertificateStatusResponse => "bad certificate status response",
            Alert::BadCertificateHashValue => "bad certificate hash value",
            Alert::UnknownPSKIdentity => "unknown PSK identity",
            Alert::CertificateRequired => "certificate required",
            Alert::NoApplicationProtocol => "no application protocol",
        }
    }
}

impl From<Alert> for Error {
    fn from(value: Alert) -> Self {
        Error::Alert(value.string())
    }
}
