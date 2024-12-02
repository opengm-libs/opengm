
pub const OidRSAEncryption: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 1, 1);

pub const OidSignatureMD2WithRSA: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 1, 2);
pub const OidSignatureMD5WithRSA: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 1, 4);
pub const OidSignatureSHA1WithRSA: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 1, 5);
pub const OidSignatureSHA256WithRSA: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 1, 11);
pub const OidSignatureSHA384WithRSA: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 1, 12);
pub const OidSignatureSHA512WithRSA: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 1, 13);
pub const OidSignatureRSAPSS: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 1, 10);
pub const OidSignatureDSAWithSHA1: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 10040, 4, 3);
pub const OidSignatureDSAWithSHA256: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 2);
pub const OidSignatureECDSAWithSHA1: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 10045, 4, 1);
pub const OidSignatureECDSAWithSHA256: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 10045, 4, 3, 2);
pub const OidSignatureECDSAWithSHA384: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 10045, 4, 3, 3);
pub const OidSignatureECDSAWithSHA512: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 10045, 4, 3, 4);
pub const OidSignatureEd25519: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 101, 112);
pub const OidSHA256: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 1);
pub const OidSHA384: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 2);
pub const OidSHA512: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 3);
pub const OidMGF1: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 1, 8);

// oidISOSignatureSHA1WithRSA means the same as oidSignatureSHA1WithRSA
// but it's specified by ISO. Microsoft's makecert.exe has been known
// to produce certificates with this OID.
pub const OidISOSignatureSHA1WithRSA: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 14, 3, 2, 29);


// publicKeyInfo
pub const OidECPublicKey: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 10045, 2, 1);
pub const OidSignatureSM2WithSM3: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 156, 10197, 1, 501);
pub const OidSm2Ecc: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 156, 10197, 1, 301);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oid() {
        println!("{}", OidSignatureMD2WithRSA);

        // assert_eq!("1.2.840.113549.1.1.2", String::from());
    }
}
