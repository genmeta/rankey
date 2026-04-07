use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("failed to parse DER: {message}"))]
    DerParse { source: der::Error, message: String },

    #[snafu(display("failed to parse PKCS#8: {message}"))]
    Pkcs8Parse {
        source: pkcs8::Error,
        message: String,
    },

    #[snafu(display("failed to parse PEM: {message}"))]
    X509Builder {
        source: x509_cert::builder::Error,
        message: String,
    },

    #[snafu(display("failed with file: {path}"))]
    Io {
        source: std::io::Error,
        path: String,
    },

    #[snafu(display("failed to verify signature: {message}"))]
    MissingAttributes { message: String },

    #[snafu(whatever, display("{message}"))]
    Whatever {
        message: String,
        #[snafu(source(from(Box<dyn std::error::Error + Send + Sync>, Some)))]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
