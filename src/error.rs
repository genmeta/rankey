use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Failed to parse DER: {message}: {source}"))]
    DerParse { source: der::Error, message: String },

    #[snafu(display("Failed to parse PKCS#8: {message}: {source}"))]
    Pkcs8Parse {
        source: pkcs8::Error,
        message: String,
    },

    #[snafu(display("Failed to parse PEM: {message}: {source}"))]
    X509Builder {
        source: x509_cert::builder::Error,
        message: String,
    },

    #[snafu(display("Failed with file: {path}: {source}"))]
    Io {
        source: std::io::Error,
        path: String,
    },

    #[snafu(display("Failed to verify signature: {message}"))]
    MissingAttributes { message: String },

    #[snafu(whatever, display("{message}"))]
    Whatever {
        message: String,
        #[snafu(source(from(Box<dyn std::error::Error>, Some)))]
        source: Option<Box<dyn std::error::Error>>,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
