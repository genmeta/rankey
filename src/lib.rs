use std::{
    fs,
    str::FromStr,
    time::{Duration, UNIX_EPOCH},
};

pub use der::EncodePem;
use der::{
    Decode,
    asn1::OctetString,
    oid::db::{rfc5280::*, rfc5912::ID_EXTENSION_REQ},
    zeroize::Zeroizing,
};
pub use p384::pkcs8::LineEnding;
use p384::{
    ecdsa::{self, SigningKey},
    elliptic_curve::Generate,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use rand::rng;
use sha1::{Digest, Sha1};
use snafu::{ResultExt, whatever};
use x509_cert::{
    Certificate,
    builder::{
        Builder, CertificateBuilder,
        profile::{self, cabf::tls::CertificateType},
    },
    certificate::CertificateInner,
    der::{DecodePem, asn1::Ia5String},
    ext::{
        Extension,
        pkix::{
            CrlReason, ExtendedKeyUsage, KeyUsage, SubjectAltName, SubjectKeyIdentifier,
            name::GeneralName,
        },
    },
    name::Name,
    request::{CertReq, RequestBuilder},
    serial_number::SerialNumber,
    time::Validity,
};

use crate::{
    error::{DerParseSnafu, Error, IoSnafu, Pkcs8ParseSnafu, Result, X509BuilderSnafu},
    util::verify_signature,
};

pub mod error;
mod ocsp;
mod util;

fn load_certificate_from_pem_file(path: &str) -> Result<Certificate> {
    Certificate::from_pem(&fs::read_to_string(path).context(IoSnafu {
        path: path.to_string(),
    })?)
    .context(DerParseSnafu {
        message: format!("failed to parse certificate from PEM: {path}"),
    })
}

fn load_signing_key_from_pem_file(path: &str) -> Result<SigningKey> {
    SigningKey::from_pkcs8_pem(&fs::read_to_string(path).context(IoSnafu {
        path: path.to_string(),
    })?)
    .context(Pkcs8ParseSnafu {
        message: format!("failed to parse signing key from PEM: {path}"),
    })
}

/// Generates a new `secp384r1` elliptic curve private key.
///
/// The key is generated randomly and returned in PKCS#8 PEM format.
/// The output `String` is wrapped in `Zeroizing` to ensure its contents
/// are securely zeroed from memory when dropped, enhancing security.
///
/// # Returns
///
/// A `pkcs8::Result` containing the PEM-encoded private key string on success,
/// or an error if key generation or encoding fails.
pub fn generate_secp384r1_key() -> pkcs8::Result<Zeroizing<String>> {
    let secret_key = SigningKey::generate();
    secret_key.to_pkcs8_pem(LineEnding::LF)
}

/// Generates a Certificate Signing Request (CSR) using the provided private key and subject details.
///
/// This function takes a PEM-encoded private key, country code, common name, and a list of
/// subject alternative names, then constructs and signs an X.509 Certificate Signing Request.
///
/// # Arguments
///
/// * `key_pem` - The private key in PKCS#8 PEM format, used to sign the CSR.
/// * `country` - The two-letter country code (e.g., "US", "GB") for the CSR's subject.
/// * `common_name` - The common name (e.g., domain name, organization name) for the CSR's subject.
/// * `subject_alt_names` - A slice of strings representing Subject Alternative Names (SANs)
///   to be included in the CSR, such as domain names or IP addresses.
///
/// # Returns
///
/// A `Result` containing the generated `CertReq` on success, or an error if
/// key parsing, subject name parsing, SAN creation, or CSR building fails.
pub fn generate_csr(
    key_pem: &str,
    country: &str,
    common_name: &str,
    subject_alt_names: &[&str],
) -> Result<CertReq> {
    let signing_key = SigningKey::from_pkcs8_pem(key_pem).context(Pkcs8ParseSnafu {
        message: "failed to parse signing key from PEM",
    })?;
    let subject =
        Name::from_str(&format!("CN={common_name},C={country}")).context(DerParseSnafu {
            message: format!("failed to parse subject name: CN={common_name}, C={country}"),
        })?;

    let san = create_subject_alt_names(subject_alt_names)?;
    let cert_req = build_csr(subject, san, &signing_key).context(X509BuilderSnafu {
        message: "failed to build CSR",
    })?;

    Ok(cert_req)
}

/// Converts a slice of string references into a `SubjectAltName` extension for X.509 certificates.
fn create_subject_alt_names(subject_alt_names: &[&str]) -> Result<SubjectAltName> {
    let mut san = Vec::with_capacity(subject_alt_names.len());
    for san_name in subject_alt_names {
        san.push(GeneralName::DnsName(Ia5String::new(san_name).context(
            DerParseSnafu {
                message: format!("failed to parse SAN name: {san_name}"),
            },
        )?));
    }
    Ok(SubjectAltName(san))
}

/// Builds a Certificate Signing Request (CSR) using the provided subject,
/// Subject Alternative Names (SANs), and a signing key.
fn build_csr(
    subject: Name,
    san: SubjectAltName,
    signing_key: &SigningKey,
) -> x509_cert::builder::Result<CertReq> {
    let mut builder = RequestBuilder::new(subject)?;
    builder.add_extension(&san)?;
    let cert_req = builder.build::<_, ecdsa::DerSignature>(signing_key)?;
    Ok(cert_req)
}

/// Signs a Certificate Signing Request (CSR) using the provided Certificate Authority (CA)
/// certificate and private key, issuing a new X.509 certificate.
///
/// # Arguments
///
/// * `csr_pem` - A string slice containing the PEM-encoded Certificate Signing Request.
/// * `ca_cert_path` - The file path to the CA's X.509 certificate in PEM format.
/// * `ca_key_path` - The file path to the CA's private key in PKCS#8 PEM format.
/// * `validity_seconds` - The number of seconds for which the issued certificate will be valid from now.
///
/// # Returns
///
/// A `Result<CertificateInner>` which is `Ok(CertificateInner)` on successful
/// issuance and signing of the certificate, or an error if any step fails.
pub fn sign_certificate(
    csr_pem: &str,
    ca_cert_path: &str,
    ca_key_path: &str,
    validity_seconds: u64,
) -> Result<CertificateInner> {
    // 加载CA证书和私钥
    let ca_cert = load_certificate_from_pem_file(ca_cert_path)?;
    let ca_signing_key = load_signing_key_from_pem_file(ca_key_path)?;

    // 解析CSR并提取关键信息
    let csr = CertReq::from_pem(csr_pem).context(DerParseSnafu {
        message: "failed to parse CSR from PEM",
    })?;
    let san = extract_san(&csr)?;

    let public_key = &csr.info.public_key;

    // 验证 CSR 签名
    verify_signature(&csr)?;

    // 准备证书元数据
    let serial_number = SerialNumber::generate(&mut rng());
    let validity =
        Validity::from_now(Duration::from_secs(validity_seconds)).context(DerParseSnafu {
            message: "failed to create certificate validity period",
        })?;

    // 构建扩展项
    let public_key_hash = Sha1::digest(public_key.subject_public_key.raw_bytes());
    let ski = SubjectKeyIdentifier(OctetString::new(public_key_hash.as_slice()).context(
        DerParseSnafu {
            message: format!("failed to create SubjectKeyIdentifier: {public_key_hash:?}"),
        },
    )?);

    // 构建并签发证书
    let profile = profile::cabf::tls::Subscriber {
        certificate_type: CertificateType::domain_validated(
            csr.info.subject.clone(),
            san.0.clone(),
        )
        .context(X509BuilderSnafu {
            message: format!(
                "failed to create certificate type for subject: {} and SANs: {san:?}",
                csr.info.subject
            ),
        })?,
        issuer: ca_cert.tbs_certificate().subject().clone(),
        client_auth: true,
    };

    // 构建证书
    let mut builder = CertificateBuilder::new(profile, serial_number, validity, public_key.clone())
        .context(X509BuilderSnafu {
            message: "failed to create certificate builder",
        })?;
    builder.add_extension(&san).context(DerParseSnafu {
        message: format!("failed to add SAN extension: {san:?}"),
    })?;
    builder.add_extension(&ski).context(DerParseSnafu {
        message: format!("failed to add SKI extension: {ski:?}"),
    })?;
    builder
        .build::<_, ecdsa::DerSignature>(&ca_signing_key)
        .context(X509BuilderSnafu {
            message: "failed to build certificate",
        })
}

/// Signs a DER-encoded OCSP response with `good` status for the provided leaf certificate.
///
/// This is intended for OCSP stapling use cases where the caller already has a leaf certificate
/// and needs a short-lived OCSP response signed by the issuer.
pub fn sign_good_ocsp_response(
    cert_pem: &str,
    ca_cert_path: &str,
    ca_key_path: &str,
    validity_seconds: u64,
) -> Result<Vec<u8>> {
    let cert = Certificate::from_pem(cert_pem).context(DerParseSnafu {
        message: "failed to parse leaf certificate from PEM",
    })?;
    let ca_cert = load_certificate_from_pem_file(ca_cert_path)?;
    let ca_signing_key = load_signing_key_from_pem_file(ca_key_path)?;

    if cert.tbs_certificate().issuer() != ca_cert.tbs_certificate().subject() {
        whatever!("leaf certificate issuer does not match provided CA subject");
    }

    ocsp::sign_good_ocsp_response(&cert, &ca_cert, &ca_signing_key, validity_seconds)
}

/// Signs a DER-encoded OCSP response with `revoked` status for the provided leaf certificate.
pub fn sign_revoked_ocsp_response(
    cert_pem: &str,
    ca_cert_path: &str,
    ca_key_path: &str,
    revoked_at_unix: i64,
    revocation_reason: Option<u32>,
    validity_seconds: u64,
) -> Result<Vec<u8>> {
    let cert = Certificate::from_pem(cert_pem).context(DerParseSnafu {
        message: "failed to parse leaf certificate from PEM",
    })?;
    let ca_cert = load_certificate_from_pem_file(ca_cert_path)?;
    let ca_signing_key = load_signing_key_from_pem_file(ca_key_path)?;

    if cert.tbs_certificate().issuer() != ca_cert.tbs_certificate().subject() {
        whatever!("leaf certificate issuer does not match provided CA subject");
    }

    let revoked_at_secs = revoked_at_unix
        .try_into()
        .whatever_context("OCSP revocation timestamp must be non-negative")?;
    let revoked_at = match UNIX_EPOCH.checked_add(Duration::from_secs(revoked_at_secs)) {
        Some(revoked_at) => revoked_at,
        None => whatever!("failed to calculate OCSP revocation time"),
    };
    let revocation_reason = revocation_reason.map(crl_reason_from_u32).transpose()?;

    ocsp::sign_revoked_ocsp_response(
        &cert,
        &ca_cert,
        &ca_signing_key,
        revoked_at,
        revocation_reason,
        validity_seconds,
    )
}

/// Signs a DER-encoded OCSP response with `unknown` status for the provided leaf certificate.
pub fn sign_unknown_ocsp_response(
    cert_pem: &str,
    ca_cert_path: &str,
    ca_key_path: &str,
    validity_seconds: u64,
) -> Result<Vec<u8>> {
    let cert = Certificate::from_pem(cert_pem).context(DerParseSnafu {
        message: "failed to parse leaf certificate from PEM",
    })?;
    let ca_cert = load_certificate_from_pem_file(ca_cert_path)?;
    let ca_signing_key = load_signing_key_from_pem_file(ca_key_path)?;

    if cert.tbs_certificate().issuer() != ca_cert.tbs_certificate().subject() {
        whatever!("leaf certificate issuer does not match provided CA subject");
    }

    ocsp::sign_unknown_ocsp_response(&cert, &ca_cert, &ca_signing_key, validity_seconds)
}

fn crl_reason_from_u32(reason: u32) -> Result<CrlReason> {
    match reason {
        0 => Ok(CrlReason::Unspecified),
        1 => Ok(CrlReason::KeyCompromise),
        2 => Ok(CrlReason::CaCompromise),
        3 => Ok(CrlReason::AffiliationChanged),
        4 => Ok(CrlReason::Superseded),
        5 => Ok(CrlReason::CessationOfOperation),
        6 => Ok(CrlReason::CertificateHold),
        8 => Ok(CrlReason::RemoveFromCRL),
        9 => Ok(CrlReason::PrivilegeWithdrawn),
        10 => Ok(CrlReason::AaCompromise),
        _ => whatever!("invalid CRL reason: {reason}"),
    }
}

/// Extracts DNS names from a PEM-encoded Certificate Signing Request (CSR).
///
/// # Arguments
///
/// * `csr_pem` - A string slice containing the PEM-encoded CSR.
///
/// # Returns
///
/// A `Result<Vec<String>>` containing DNS names on success.
pub fn extract_dns_names_from_csr_pem(csr_pem: &str) -> Result<Vec<String>> {
    let csr = CertReq::from_pem(csr_pem).context(DerParseSnafu {
        message: "failed to parse CSR from PEM",
    })?;

    let san = extract_san(&csr)?;

    let dns_names = san
        .0
        .iter()
        .filter_map(|name| match name {
            GeneralName::DnsName(dns_name) => Some(dns_name.to_string()),
            _ => None,
        })
        .collect();

    Ok(dns_names)
}

/// Extracts the Subject Alternative Name (SAN) extension from a Certificate Signing Request (CSR).
fn extract_san(csr: &CertReq) -> Result<SubjectAltName> {
    let ext_req_attr = csr
        .info
        .attributes
        .iter()
        .find(|attr| attr.oid == ID_EXTENSION_REQ)
        .ok_or(Error::MissingAttributes {
            message: "ID_EXTENSION_REQ attribute not found in CSR".to_string(),
        })?;

    let extensions = ext_req_attr
        .values
        .get(0)
        .ok_or(Error::MissingAttributes {
            message: "No extension request value found in CSR".to_string(),
        })?
        .decode_as::<Vec<Extension>>()
        .context(DerParseSnafu {
            message: "failed to parse extension request value".to_string(),
        })?;

    let san = extensions
        .iter()
        .find(|ext| ext.extn_id == ID_CE_SUBJECT_ALT_NAME)
        .ok_or(Error::MissingAttributes {
            message: "SubjectAltName extension not found in CSR".to_string(),
        })?;

    SubjectAltName::from_der(san.extn_value.as_ref()).context(DerParseSnafu {
        message: "failed to parse SubjectAltName from CSR".to_string(),
    })
}

/// 证书信息结构体,包含证书的所有关键信息
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CertificateInfo {
    /// 证书主体(Subject)
    pub subject: String,
    /// 证书颁发者(Issuer)
    pub issuer: String,
    /// 证书有效期开始时间
    pub not_before: String,
    /// 证书有效期结束时间
    pub not_after: String,
    /// 主体备用名称(Subject Alternative Names)
    pub subject_alt_names: Vec<String>,
    /// 扩展密钥用途(Extended Key Usage)
    pub extended_key_usage: Vec<String>,
    /// 密钥用途(Key Usage)
    pub key_usage: Vec<String>,
    /// 序列号
    pub serial_number: String,
    /// 公钥算法
    pub public_key_algorithm: String,
    /// 签名算法
    pub signature_algorithm: String,
}

impl std::fmt::Display for CertificateInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Subject: {}", self.subject)?;
        writeln!(f, "Issuer: {}", self.issuer)?;
        writeln!(f, "Serial Number: {}", self.serial_number)?;
        writeln!(f, "Validity:")?;
        writeln!(f, "Not Before: {}", self.not_before)?;
        writeln!(f, "Not After: {}", self.not_after)?;
        writeln!(f, "Public Key Algorithm: {}", self.public_key_algorithm)?;
        writeln!(f, "Signature Algorithm: {}", self.signature_algorithm)?;

        if !self.subject_alt_names.is_empty() {
            writeln!(
                f,
                "X509v3 Subject Alternative Name: {}",
                self.subject_alt_names.join(", ")
            )?;
        }

        if !self.key_usage.is_empty() {
            writeln!(f, "X509v3 Key Usage: {}", self.key_usage.join(", "))?;
        }

        if !self.extended_key_usage.is_empty() {
            writeln!(
                f,
                "X509v3 Extended Key Usage: {}",
                self.extended_key_usage.join(", ")
            )?;
        }

        Ok(())
    }
}

/// 将 OID 转换为 Extended Key Usage 的可读名称
fn oid_to_eku_name(oid: &der::asn1::ObjectIdentifier) -> String {
    match *oid {
        ID_KP_SERVER_AUTH => "serverAuth".to_string(),
        ID_KP_CLIENT_AUTH => "clientAuth".to_string(),
        ID_KP_CODE_SIGNING => "codeSigning".to_string(),
        ID_KP_EMAIL_PROTECTION => "emailProtection".to_string(),
        ID_KP_TIME_STAMPING => "timeStamping".to_string(),
        _ => format!("{oid}"),
    }
}

/// 将 OID 转换为算法名称
fn oid_to_alg_name(oid: &der::asn1::ObjectIdentifier) -> String {
    use der::oid::db::rfc5912;
    match *oid {
        rfc5912::ID_EC_PUBLIC_KEY => "ECDSA".to_string(),
        rfc5912::ECDSA_WITH_SHA_384 => "ECDSA with SHA-384".to_string(),
        _ => format!("{oid}"),
    }
}

/// 从PEM编码的证书中提取所有关键信息
///
/// 此函数解析X.509证书并提取包括主体、颁发者、有效期、
/// Subject Alternative Names、Extended Key Usage等在内的所有重要信息。
///
/// # Arguments
///
/// * `cert_pem` - PEM格式的证书字符串
///
/// # Returns
///
/// 返回`Result<CertificateInfo>`，成功时包含证书的所有信息，
/// 失败时返回错误信息。
pub fn extract_certificate_info(cert_pem: &str) -> Result<CertificateInfo> {
    let cert = Certificate::from_pem(cert_pem).context(DerParseSnafu {
        message: "failed to parse certificate from PEM",
    })?;

    let tbs = cert.tbs_certificate();

    // 提取基本信息
    let subject = tbs.subject().to_string();
    let issuer = tbs.issuer().to_string();
    let serial_number = tbs
        .serial_number()
        .as_bytes()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>();

    // 提取有效期
    let not_before = format_time(&tbs.validity().not_before);
    let not_after = format_time(&tbs.validity().not_after);

    // 提取公钥和签名算法
    let public_key_algorithm = oid_to_alg_name(&tbs.subject_public_key_info().algorithm.oid);
    let signature_algorithm = oid_to_alg_name(&tbs.signature().oid);

    // 提取扩展信息
    let mut subject_alt_names = Vec::new();
    let mut extended_key_usage = Vec::new();
    let mut key_usage = Vec::new();

    if let Some(extensions) = tbs.extensions() {
        for ext in extensions.iter() {
            // 提取 Subject Alternative Names
            if ext.extn_id == ID_CE_SUBJECT_ALT_NAME
                && let Ok(san) = SubjectAltName::from_der(ext.extn_value.as_ref())
            {
                for name in san.0.iter() {
                    match name {
                        GeneralName::DnsName(dns) => {
                            subject_alt_names.push(format!("DNS:{dns}"));
                        }
                        GeneralName::IpAddress(ip) => {
                            subject_alt_names.push(format!("IP:{ip:?}"));
                        }
                        GeneralName::Rfc822Name(email) => {
                            subject_alt_names.push(format!("Email:{email}"));
                        }
                        GeneralName::UniformResourceIdentifier(uri) => {
                            subject_alt_names.push(format!("URI:{uri}"));
                        }
                        _ => {}
                    }
                }
            }

            // 提取 Extended Key Usage
            if ext.extn_id == ID_CE_EXT_KEY_USAGE
                && let Ok(eku) = ExtendedKeyUsage::from_der(ext.extn_value.as_ref())
            {
                for usage in eku.0.iter() {
                    extended_key_usage.push(oid_to_eku_name(usage));
                }
            }

            // 提取 Key Usage
            if ext.extn_id == ID_CE_KEY_USAGE
                && let Ok(ku) = KeyUsage::from_der(ext.extn_value.as_ref())
            {
                if ku.digital_signature() {
                    key_usage.push("Digital Signature".to_string());
                }
                if ku.non_repudiation() {
                    key_usage.push("Non Repudiation".to_string());
                }
                if ku.key_encipherment() {
                    key_usage.push("Key Encipherment".to_string());
                }
                if ku.data_encipherment() {
                    key_usage.push("Data Encipherment".to_string());
                }
                if ku.key_agreement() {
                    key_usage.push("Key Agreement".to_string());
                }
                if ku.key_cert_sign() {
                    key_usage.push("Certificate Sign".to_string());
                }
                if ku.crl_sign() {
                    key_usage.push("CRL Sign".to_string());
                }
                if ku.encipher_only() {
                    key_usage.push("Encipher Only".to_string());
                }
                if ku.decipher_only() {
                    key_usage.push("Decipher Only".to_string());
                }
            }
        }
    }

    Ok(CertificateInfo {
        subject,
        issuer,
        not_before,
        not_after,
        subject_alt_names,
        extended_key_usage,
        key_usage,
        serial_number,
        public_key_algorithm,
        signature_algorithm,
    })
}

/// 格式化时间为可读字符串
fn format_time(time: &x509_cert::time::Time) -> String {
    let dt = time.to_date_time();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minutes(),
        dt.seconds()
    )
}

#[cfg(test)]
mod tests {
    use der::Decode;

    use super::{
        ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus},
        *,
    };

    fn issue_test_leaf_cert() -> String {
        let key = generate_secp384r1_key().expect("failed to generate key");
        let csr = generate_csr(
            &key,
            "CN",
            "ocsp-test.pilot.genmeta.net",
            &["ocsp-test.pilot.genmeta.net"],
        )
        .expect("failed to generate CSR");
        let csr_pem = csr.to_pem(LineEnding::LF).unwrap();
        let cert = sign_certificate(
            &csr_pem,
            "intermediate/intermediate.crt",
            "intermediate/intermediate.pkcs8.key",
            365 * 24 * 60 * 60,
        )
        .expect("failed to sign leaf certificate");

        cert.to_pem(LineEnding::LF).unwrap()
    }

    fn decode_basic_ocsp_response(ocsp_der: &[u8]) -> BasicOcspResponse {
        let ocsp = OcspResponse::from_der(ocsp_der).expect("failed to decode OCSP response");
        assert_eq!(ocsp.response_status, OcspResponseStatus::Successful);

        let response_bytes = ocsp.response_bytes.expect("Missing OCSP response bytes");
        BasicOcspResponse::from_der(response_bytes.response.as_bytes())
            .expect("failed to decode basic OCSP response")
    }

    #[test]
    fn test_generate_secp384r1_key() {
        let _key = generate_secp384r1_key().expect("failed to generate key");
    }

    #[test]
    fn test_generate_csr() {
        let temp_dir = std::env::temp_dir();
        let key_path = temp_dir.join("test.key");
        let csr_path = temp_dir.join("test.csr");
        let key = generate_secp384r1_key().expect("failed to generate key");
        fs::write(&key_path, key.as_bytes()).expect("failed to write key to file");
        println!("Generated key at: {}", key_path.display());
        let key = fs::read_to_string(&key_path).expect("failed to read key file");
        println!("Key content:\n{key}");

        let result = generate_csr(
            &key,
            "CN",
            "borber.pilot.genmeta.net",
            &[
                "borber.pilot.genmeta.net",
                "api.borber.pilot.genmeta.net",
                "www.borber.pilot.genmeta.net",
            ],
        );
        assert!(result.is_ok());
        let csr = result.unwrap();
        let csr_pem = csr.to_pem(LineEnding::LF).unwrap();
        fs::write(&csr_path, csr_pem).expect("failed to write CSR to file");
        println!("Generated CSR at: {}", csr_path.display());
        let csr = fs::read_to_string(&csr_path).expect("failed to read CSR file");
        println!("CSR content:\n{csr}");
        let base64_csr = base64_simd::STANDARD.encode_to_string(csr.as_bytes());
        println!("Base64 Encoded CSR:\n{base64_csr}");
    }

    #[test]
    fn test_sign_certificate() {
        let temp_dir = std::env::temp_dir();
        let csr_path = temp_dir.join("test.csr");
        let csr_pem = if csr_path.exists() {
            fs::read_to_string(&csr_path).expect("failed to read CSR file")
        } else {
            let key = generate_secp384r1_key().expect("failed to generate key");
            let csr = generate_csr(
                &key,
                "CN",
                "borber.pilot.genmeta.net",
                &[
                    "borber.pilot.genmeta.net",
                    "api.borber.pilot.genmeta.net",
                    "www.borber.pilot.genmeta.net",
                ],
            )
            .expect("failed to generate CSR");
            let csr_pem = csr
                .to_pem(LineEnding::LF)
                .expect("failed to encode CSR PEM");
            fs::write(&csr_path, &csr_pem).expect("failed to write CSR file");
            csr_pem
        };

        let dns_names = extract_dns_names_from_csr_pem(csr_pem.as_str())
            .expect("failed to extract DNS names from CSR");
        println!("Extracted DNS names from CSR: {:?}", dns_names);

        let result = sign_certificate(
            &csr_pem,
            "intermediate/intermediate.crt",
            "intermediate/intermediate.pkcs8.key",
            365 * 24 * 60 * 60, // 365 days in seconds
        );

        assert!(result.is_ok());
        let cert = result.unwrap();
        let mut cert_pem = cert.to_pem(LineEnding::LF).unwrap();
        // 将 intermediate CA 证书 附加到生成的证书中
        let ca_cert_pem = fs::read_to_string("intermediate/intermediate.crt")
            .expect("failed to read CA certificate file");
        cert_pem.push_str(&ca_cert_pem);

        let cert_path = temp_dir.join("signed_certificate.pem");
        fs::write(&cert_path, cert_pem).expect("failed to write certificate to file");
        println!("Signed certificate at: {}", cert_path.display());
        let cert = fs::read_to_string(&cert_path).expect("failed to read certificate file");
        println!("Certificate content:\n{cert}");
    }

    #[test]
    fn test_extract_dns_names_from_csr_pem() {
        let key = generate_secp384r1_key().expect("failed to generate key");
        let subject_alt_names = &["test.example.com", "api.example.com", "www.example.com"];
        let csr = generate_csr(&key, "US", "example.com", subject_alt_names)
            .expect("failed to generate CSR");
        let csr_pem = csr.to_pem(LineEnding::LF).unwrap();

        let result = extract_dns_names_from_csr_pem(&csr_pem);
        assert!(result.is_ok());
        let dns_names = result.unwrap();

        assert_eq!(dns_names.len(), 3);
        assert_eq!(dns_names[0], "test.example.com");
        assert_eq!(dns_names[1], "api.example.com");
        assert_eq!(dns_names[2], "www.example.com");
    }

    #[test]
    fn test_extract_certificate_info() {
        let temp_dir = std::env::temp_dir();
        let cert_path = temp_dir.join("signed_certificate.pem");

        // 首先确保证书存在
        if !cert_path.exists() {
            // 运行 test_sign_certificate 来生成证书
            test_sign_certificate();
        }

        let cert_pem_full =
            fs::read_to_string(&cert_path).expect("failed to read certificate file");

        // 提取第一个证书 (服务器证书)
        let cert_pem = if let Some(end_pos) = cert_pem_full.find("-----END CERTIFICATE-----") {
            &cert_pem_full[..end_pos + "-----END CERTIFICATE-----".len()]
        } else {
            &cert_pem_full
        };

        let result = extract_certificate_info(cert_pem);
        if let Err(e) = &result {
            eprintln!("Error extracting certificate info: {}", e);
        }
        assert!(result.is_ok());

        let cert_info = result.unwrap();
        println!("\n{}", cert_info);

        // 验证基本信息存在
        assert!(!cert_info.subject.is_empty());
        assert!(!cert_info.issuer.is_empty());
        assert!(!cert_info.not_before.is_empty());
        assert!(!cert_info.not_after.is_empty());
        assert!(!cert_info.subject_alt_names.is_empty());
    }

    #[test]
    fn test_sign_good_ocsp_response() {
        let cert_pem = issue_test_leaf_cert();

        let ocsp_der = sign_good_ocsp_response(
            &cert_pem,
            "intermediate/intermediate.crt",
            "intermediate/intermediate.pkcs8.key",
            3 * 60 * 60,
        )
        .expect("failed to sign OCSP response");

        let basic = decode_basic_ocsp_response(&ocsp_der);
        assert_eq!(basic.tbs_response_data.responses.len(), 1);

        let single_response = &basic.tbs_response_data.responses[0];
        assert!(matches!(single_response.cert_status, CertStatus::Good(_)));
        assert!(single_response.next_update.is_some());
    }

    #[test]
    fn test_sign_revoked_ocsp_response() {
        let cert_pem = issue_test_leaf_cert();

        let ocsp_der = sign_revoked_ocsp_response(
            &cert_pem,
            "intermediate/intermediate.crt",
            "intermediate/intermediate.pkcs8.key",
            1_700_000_000,
            Some(1),
            3 * 60 * 60,
        )
        .expect("failed to sign revoked OCSP response");

        let basic = decode_basic_ocsp_response(&ocsp_der);
        assert_eq!(basic.tbs_response_data.responses.len(), 1);

        let single_response = &basic.tbs_response_data.responses[0];
        assert!(matches!(
            single_response.cert_status,
            CertStatus::Revoked(_)
        ));
    }

    #[test]
    fn test_sign_unknown_ocsp_response() {
        let cert_pem = issue_test_leaf_cert();

        let ocsp_der = sign_unknown_ocsp_response(
            &cert_pem,
            "intermediate/intermediate.crt",
            "intermediate/intermediate.pkcs8.key",
            3 * 60 * 60,
        )
        .expect("failed to sign unknown OCSP response");

        let basic = decode_basic_ocsp_response(&ocsp_der);
        assert_eq!(basic.tbs_response_data.responses.len(), 1);

        let single_response = &basic.tbs_response_data.responses[0];
        assert!(matches!(
            single_response.cert_status,
            CertStatus::Unknown(_)
        ));
    }
}
