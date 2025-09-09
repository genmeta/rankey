# rankey

`rankey` 是一个用于处理 X.509 证书和 `secp384r1` 密钥的 Rust 库。它提供了一套简单易用的 API，用于生成密钥、创建证书签名请求 (CSR)，以及使用证书颁发机构 (CA) 对 CSR 进行签名。

## 功能特性

- **密钥生成**: 快速生成符合 `secp384r1` 标准的椭圆曲线私钥，并以 PKCS#8 PEM 格式输出。
- **CSR 创建**: 根据提供的国家、通用名称和主题备用名称 (SAN) 生成 X.509 证书签名请求。
- **证书签名**: 使用您自己的 CA 证书和私钥对 CSR 进行签名，轻松颁发新的 X.509 证书。
- **信息提取**: 从 CSR 中轻松提取 DNS 名称等信息。
- **安全设计**: 使用 `Zeroizing` 来处理敏感的密钥材料，确保其在内存中被安全擦除。

## 安装

将以下内容添加到您的 `Cargo.toml` 文件中：

```toml
[dependencies]
rankey = "0.1.0"
```

## API 概览

- `generate_secp384r1_key() -> pkcs8::Result<Zeroizing<String>>`
  - 生成一个新的 `secp384r1` 私钥，并以 PKCS#8 PEM 格式返回。

- `generate_csr(key_pem: &str, country: &str, common_name: &str, subject_alt_names: &[&str]) -> Result<CertReq>`
  - 使用给定的私钥和主题信息创建一个证书签名请求 (CSR)。

- `sign_certificate(csr_pem: &str, ca_cert_path: &str, ca_key_path: &str, validity_days: u64) -> Result<CertificateInner>`
  - 使用指定的 CA 证书和私钥来签署一个 CSR，并颁发一个新的证书。

- `extract_dns_names_from_csr_pem(csr_pem: &str) -> Result<Vec<String>>`
  - 从一个 PEM 格式的 CSR 中提取所有的 DNS 主题备用名称 (SAN)。

## 许可证

该项目采用 [MIT 许可证](LICENSE)。
