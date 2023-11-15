use std::{ffi, io};

use tokio::sync::{mpsc, watch};
use tokio::task;

use rsdsl_ip_config::{Ipv4Config, Ipv6Config};
use thiserror::Error;

/// An external error that prevents a supervisor from functioning.
#[derive(Debug, Error)]
pub enum Error {
    #[error("got no ipv4 address")]
    NoIpv4Addr,
    #[error("got no ipv4 primary dns")]
    NoIpv4Dns1,
    #[error("got no ipv4 secondary dns")]
    NoIpv4Dns2,
    #[error("got no ipv6 link-local address")]
    NoIpv6Local,
    #[error("got no ipv6 link-local peer address")]
    NoIpv6Remote,
    #[error("no mac address on interface {0}")]
    NoMacAddress(String),
    #[error("no magic number negotiated locally")]
    NoMagicNumber,
    #[error("ipv4 configuration update channel is closed")]
    V4ChannelClosed,
    #[error("ipv6 configuration update channel is closed")]
    V6ChannelClosed,

    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("interface name contains nul byte: {0}")]
    Nul(#[from] ffi::NulError),

    #[error("error joining tokio task: {0}")]
    Join(#[from] task::JoinError),
    #[error("error sending Option<Ipv4Config> to tokio mpsc channel: {0}")]
    MpscSendV4(#[from] mpsc::error::SendError<Option<Ipv4Config>>),
    #[error("error sending Option<Ipv6Config> to tokio mpsc channel: {0}")]
    MpscSendV6(#[from] mpsc::error::SendError<Option<Ipv6Config>>),
    #[error("error receiving from tokio watch channel: {0}")]
    WatchRecv(#[from] watch::error::RecvError),

    #[error("error retrieving local mac address: {0}")]
    MacAddress(#[from] mac_address::MacAddressError),
    #[error("ppproperly packet (de)serialization failed: {0}")]
    Ppproperly(#[from] ppproperly::Error),
    #[error("serde_json (de)serialization failed: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

/// An alias for a [`std::result::Result`] with the [`enum@Error`] type of this crate.
pub type Result<T> = std::result::Result<T, Error>;
