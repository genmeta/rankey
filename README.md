# rankey

`rankey` 是用于 X.509 证书、OCSP 响应和 `secp384r1` 密钥管理的 Rust 库。它提供面向证书签发流程的基础 API：生成私钥、创建证书签名请求 (CSR)、使用 CA 证书和私钥签发叶子证书、提取证书信息，以及生成 OCSP 响应。

## 功能特性

- **密钥生成**：生成 `secp384r1` 椭圆曲线私钥，并以 PKCS#8 PEM 格式返回。
- **CSR 创建**：根据国家、通用名称和主题备用名称 (SAN) 构造并签名 X.509 CSR。
- **证书签名**：使用 CA 证书和 PKCS#8 私钥签署 CSR，生成 X.509 叶子证书。
- **信息提取**：从 CSR 中提取 DNS SAN；从证书 PEM 中提取主题、签发者、有效期、SAN、Key Usage、Extended Key Usage、序列号和算法信息。
- **OCSP 响应**：为叶子证书生成 `good`、`revoked` 或 `unknown` 状态的 DER 编码 OCSP 响应。
- **密钥材料保护**：生成的 PEM 私钥使用 `Zeroizing<String>` 承载，降低敏感内容在内存中残留的风险。

## 安装

将以下内容添加到 `Cargo.toml`：

```toml
[dependencies]
rankey = "0.2.1"
```

默认启用 `serde` feature。如需关闭默认 feature：

```toml
[dependencies]
rankey = { version = "0.2.1", default-features = false }
```

## API 概览

- `generate_secp384r1_key() -> pkcs8::Result<Zeroizing<String>>`
  - 生成新的 `secp384r1` 私钥，并以 PKCS#8 PEM 格式返回。

- `generate_csr(key_pem: &str, country: &str, common_name: &str, subject_alt_names: &[&str]) -> Result<CertReq>`
  - 使用私钥和主题信息创建 CSR。

- `sign_certificate(csr_pem: &str, ca_cert_path: &str, ca_key_path: &str, validity_seconds: u64) -> Result<CertificateInner>`
  - 使用 CA 证书和私钥签署 CSR，签发有效期为 `validity_seconds` 秒的证书。

- `extract_dns_names_from_csr_pem(csr_pem: &str) -> Result<Vec<String>>`
  - 从 PEM 格式 CSR 中提取 DNS SAN。

- `extract_certificate_info(cert_pem: &str) -> Result<CertificateInfo>`
  - 从 PEM 格式证书中提取可展示的证书信息。

- `sign_good_ocsp_response(cert_pem: &str, ca_cert_path: &str, ca_key_path: &str, validity_seconds: u64) -> Result<Vec<u8>>`
  - 为叶子证书生成 `good` 状态的 DER 编码 OCSP 响应。

- `sign_revoked_ocsp_response(cert_pem: &str, ca_cert_path: &str, ca_key_path: &str, revoked_at_unix: i64, revocation_reason: Option<u32>, validity_seconds: u64) -> Result<Vec<u8>>`
  - 为叶子证书生成 `revoked` 状态的 DER 编码 OCSP 响应。

- `sign_unknown_ocsp_response(cert_pem: &str, ca_cert_path: &str, ca_key_path: &str, validity_seconds: u64) -> Result<Vec<u8>>`
  - 为叶子证书生成 `unknown` 状态的 DER 编码 OCSP 响应。

## 许可证

该项目采用 [MIT 许可证](LICENSE)。
