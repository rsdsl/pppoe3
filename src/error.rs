use std::{ffi, io};

use tokio::sync::watch;

use thiserror::Error;

/// An external error that prevents a supervisor from functioning.
#[derive(Debug, Error)]
pub enum Error {
    #[error("no mac address on interface {0}")]
    NoMacAddress(String),
    #[error("no magic number negotiated locally")]
    NoMagicNumber,

    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("interface name contains nul byte: {0}")]
    Nul(#[from] ffi::NulError),

    #[error("error receiving from tokio watch channel: {0}")]
    WatchRecv(#[from] watch::error::RecvError),

    #[error("error retrieving local mac address: {0}")]
    MacAddress(#[from] mac_address::MacAddressError),
    #[error("ppproperly packet (de)serialization failed: {0}")]
    Ppproperly(#[from] ppproperly::Error),
}

/// An alias for a [`std::result::Result`] with the [`enum@Error`] type of this crate.
pub type Result<T> = std::result::Result<T, Error>;
