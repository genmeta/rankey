use der::{Encode, oid::db::rfc5912};
use p384::ecdsa::signature::Verifier;
use pkcs8::DecodePublicKey;
use snafu::{ResultExt, whatever};
use x509_cert::request::CertReq;

use crate::error::DerParseSnafu;

/// Verifies the signature of a certificate request.
///
/// Checks if the signature algorithm is supported (currently only ECDSA with SHA-384).
/// Extracts the public key and signed data from the request, then verifies the signature
/// using the provided public key. Returns an error for unsupported algorithms or verification failures.
///
/// # Parameters
/// - `cert_req`: Reference to the certificate request containing signature, algorithm, and public key info.
///
/// # Returns
/// - `Ok(())` if signature verification succeeds.
/// - `Err` containing error description if:
///   - Unsupported algorithm is used
///   - Public key DER conversion fails
///   - Signature DER conversion fails
///   - Signature verification fails
pub fn verify_signature(cert_req: &CertReq) -> crate::error::Result<()> {
    match cert_req.algorithm.oid {
        rfc5912::ECDSA_WITH_SHA_384 => {
            let spki = cert_req.info.public_key.to_der().context(DerParseSnafu {
                message: "Failed to parse public key in CSR",
            })?;
            let signed_data = cert_req.info.to_der().context(DerParseSnafu {
                message: "Failed to parse signed data",
            })?;
            let signature_der = cert_req.signature.raw_bytes();
            let signature = p384::ecdsa::DerSignature::from_bytes(signature_der)
                .whatever_context("Failed to parse der signature")?;
            let verifying_key = p384::ecdsa::VerifyingKey::from_public_key_der(&spki)
                .whatever_context("Failed to parse verify key")?;
            verifying_key
                .verify(&signed_data, &signature)
                .whatever_context("Failed to verify")?;
        }
        _ => {
            whatever!("Unsupported algorithm");
        }
    }

    Ok(())
}
