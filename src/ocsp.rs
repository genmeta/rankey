use std::time::{Duration, SystemTime};

use der::{
    Choice, Encode, Enumerated, Sequence,
    asn1::{BitString, GeneralizedTime, Null, ObjectIdentifier, OctetString},
    oid::db::{rfc5912::ID_SHA_1, rfc6960::ID_PKIX_OCSP_BASIC},
};
use p384::ecdsa::{self, SigningKey, signature::Signer};
use sha1::{Digest, Sha1};
use snafu::{ResultExt, whatever};
use x509_cert::{
    Certificate,
    ext::{Extensions, pkix::CrlReason},
    name::Name,
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding},
};

use crate::error::{DerParseSnafu, Result};

#[derive(Clone, Debug, Default, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum Version {
    #[default]
    V1 = 0,
}

#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum ResponderId {
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    ByName(Name),

    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "true")]
    ByKey(OctetString),
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CertId {
    pub hash_algorithm: AlgorithmIdentifierOwned,
    pub issuer_name_hash: OctetString,
    pub issuer_key_hash: OctetString,
    pub serial_number: SerialNumber,
}

#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum CertStatus {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Good(Null),

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Revoked(RevokedInfo),

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    Unknown(Null),
}

impl CertStatus {
    pub fn good() -> Self {
        Self::Good(Null)
    }

    pub fn revoked(revocation_time: GeneralizedTime, revocation_reason: Option<CrlReason>) -> Self {
        Self::Revoked(RevokedInfo {
            revocation_time,
            revocation_reason,
        })
    }

    pub fn unknown() -> Self {
        Self::Unknown(Null)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
pub struct RevokedInfo {
    pub revocation_time: GeneralizedTime,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub revocation_reason: Option<x509_cert::ext::pkix::CrlReason>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SingleResponse {
    pub cert_id: CertId,
    pub cert_status: CertStatus,
    pub this_update: GeneralizedTime,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub next_update: Option<GeneralizedTime>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub single_extensions: Option<Extensions>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ResponseData {
    #[asn1(
        context_specific = "0",
        default = "Default::default",
        tag_mode = "EXPLICIT"
    )]
    pub version: Version,
    pub responder_id: ResponderId,
    pub produced_at: GeneralizedTime,
    pub responses: Vec<SingleResponse>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub response_extensions: Option<Extensions>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct BasicOcspResponse {
    pub tbs_response_data: ResponseData,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: BitString,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub certs: Option<Vec<Certificate>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ResponseBytes {
    pub response_type: ObjectIdentifier,
    pub response: OctetString,
}

#[derive(Enumerated, Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum OcspResponseStatus {
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    TryLater = 3,
    SigRequired = 5,
    Unauthorized = 6,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct OcspResponse {
    pub response_status: OcspResponseStatus,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub response_bytes: Option<ResponseBytes>,
}

fn sign_ocsp_response(
    cert: &Certificate,
    issuer: &Certificate,
    signer: &SigningKey,
    cert_status: CertStatus,
    validity_seconds: u64,
) -> Result<Vec<u8>> {
    let now = SystemTime::now();
    let next_update = match now.checked_add(Duration::from_secs(validity_seconds)) {
        Some(next_update) => next_update,
        None => whatever!("failed to calculate OCSP next_update"),
    };

    let produced_at = GeneralizedTime::try_from(now).context(DerParseSnafu {
        message: "failed to create OCSP produced_at time",
    })?;
    let next_update = GeneralizedTime::try_from(next_update).context(DerParseSnafu {
        message: "failed to create OCSP next_update time",
    })?;
    let response_data = ResponseData {
        version: Version::default(),
        responder_id: ResponderId::ByName(issuer.tbs_certificate().subject().clone()),
        produced_at,
        responses: vec![SingleResponse {
            cert_id: build_cert_id(issuer, cert)?,
            cert_status,
            this_update: produced_at,
            next_update: Some(next_update),
            single_extensions: None,
        }],
        response_extensions: None,
    };

    let signature_algorithm = signer
        .signature_algorithm_identifier()
        .whatever_context("failed to build OCSP signature algorithm identifier")?;
    let tbs_response_data = response_data.to_der().context(DerParseSnafu {
        message: "failed to encode OCSP response data to DER",
    })?;
    let signature: ecdsa::DerSignature = signer
        .try_sign(&tbs_response_data)
        .whatever_context("failed to sign OCSP response data")?;
    let signature = signature
        .to_bitstring()
        .whatever_context("failed to encode OCSP signature as bit string")?;

    let basic_response = BasicOcspResponse {
        tbs_response_data: response_data,
        signature_algorithm,
        signature,
        certs: None,
    };

    let response = OcspResponse {
        response_status: OcspResponseStatus::Successful,
        response_bytes: Some(ResponseBytes {
            response_type: ID_PKIX_OCSP_BASIC,
            response: OctetString::new(basic_response.to_der().context(DerParseSnafu {
                message: "failed to encode basic OCSP response to DER",
            })?)
            .context(DerParseSnafu {
                message: "failed to wrap basic OCSP response bytes",
            })?,
        }),
    };

    response.to_der().context(DerParseSnafu {
        message: "failed to encode OCSP response to DER",
    })
}

pub fn sign_good_ocsp_response(
    cert: &Certificate,
    issuer: &Certificate,
    signer: &SigningKey,
    validity_seconds: u64,
) -> Result<Vec<u8>> {
    sign_ocsp_response(cert, issuer, signer, CertStatus::good(), validity_seconds)
}

pub fn sign_revoked_ocsp_response(
    cert: &Certificate,
    issuer: &Certificate,
    signer: &SigningKey,
    revoked_at: SystemTime,
    revocation_reason: Option<CrlReason>,
    validity_seconds: u64,
) -> Result<Vec<u8>> {
    let revocation_time = GeneralizedTime::try_from(revoked_at).context(DerParseSnafu {
        message: "failed to create OCSP revocation time",
    })?;
    sign_ocsp_response(
        cert,
        issuer,
        signer,
        CertStatus::revoked(revocation_time, revocation_reason),
        validity_seconds,
    )
}

pub fn sign_unknown_ocsp_response(
    cert: &Certificate,
    issuer: &Certificate,
    signer: &SigningKey,
    validity_seconds: u64,
) -> Result<Vec<u8>> {
    sign_ocsp_response(
        cert,
        issuer,
        signer,
        CertStatus::unknown(),
        validity_seconds,
    )
}

fn build_cert_id(issuer: &Certificate, cert: &Certificate) -> Result<CertId> {
    let issuer_name_hash = Sha1::digest(issuer.tbs_certificate().subject().to_der().context(
        DerParseSnafu {
            message: "failed to encode issuer subject to DER",
        },
    )?);
    let issuer_key_hash = Sha1::digest(
        issuer
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .raw_bytes(),
    );

    Ok(CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: ID_SHA_1,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(issuer_name_hash.as_slice()).context(DerParseSnafu {
            message: "failed to encode issuer name hash",
        })?,
        issuer_key_hash: OctetString::new(issuer_key_hash.as_slice()).context(DerParseSnafu {
            message: "failed to encode issuer key hash",
        })?,
        serial_number: cert.tbs_certificate().serial_number().clone(),
    })
}
