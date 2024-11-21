#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid configuration")]
    InvalidConfig,

    #[error("not implementated")]
    NotImplemented,

    #[error("device tun name too long")]
    NameTooLong,

    #[error("invalid device tun name")]
    InvalidName,

    #[error("invalid address")]
    InvalidAddress,

    #[error("invalid file descriptor")]
    InvalidDescriptor,

    #[error("unsupported network layer of operation")]
    UnsupportedLayer,

    #[error("out of range integral type conversion attempted")]
    TryFromIntError,

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Nul(#[from] std::ffi::NulError),

    #[error(transparent)]
    ParseNum(#[from] std::num::ParseIntError),

    #[cfg(target_os = "windows")]
    #[error(transparent)]
    WintunError(#[from] wintun::Error),

    #[cfg(target_os = "windows")]
    #[error(transparent)]
    LibloadingError(#[from] libloading::Error),

    #[error("{0}")]
    String(String),
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        Self::String(err.to_string())
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Self::String(err)
    }
}

impl From<&String> for Error {
    fn from(err: &String) -> Self {
        Self::String(err.to_string())
    }
}

impl From<Error> for std::io::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::Io(err) => err,
            _ => std::io::Error::new(std::io::ErrorKind::Other, value),
        }
    }
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub type Result<T, E = Error> = ::std::result::Result<T, E>;
